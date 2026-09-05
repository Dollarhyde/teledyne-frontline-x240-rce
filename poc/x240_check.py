#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
Read-only exposure checker for Teledyne LeCroy Frontline analyzers.

The checker attempts anonymous FTP authentication and probes only filesystem
metadata. It also listens for the unsolicited TCF Locator.Hello event on
TCP/1534. It never retrieves file contents, uploads or deletes files, sends a
TCF command, or starts a process.

Target  : Teledyne LeCroy Frontline X240 / X240i / X500 / X500e
Finding : Anonymous FTP as root (TCP/21) and unauthenticated TCF agent (TCP/1534)
Advisory: TDY-PSG-2026-001 (CVE pending)
Patched : WPS 4.70 Beta / device firmware update
Author  : Erwin Karincic (Dollarhyde)

Exit status:
    0  No affected exposure detected
    1  Anonymous root-filesystem or dangerous TCF exposure detected
    2  Inconclusive because one or more checks could not complete

Authorized testing only. Use against equipment you own or are explicitly
permitted to test.
"""

import argparse
import ftplib
import json
import socket
import sys

EOM = b"\x03\x01"
DANGEROUS_TCF_SERVICES = {"FileSystem", "Processes", "ProcessesV1"}


def check_ftp(host, port, timeout):
    result = {
        "port": port,
        "connected": False,
        "anonymous_login": False,
        "root_filesystem_exposed": False,
        "metadata_probes": {},
        "status": "unknown",
    }
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=timeout)
        result["connected"] = True
        result["banner"] = ftp.getwelcome()
        try:
            ftp.login("anonymous", "anonymous@")
        except ftplib.error_perm as e:
            result["status"] = "anonymous_denied"
            result["detail"] = str(e)
            return result
        result["anonymous_login"] = True
        try:
            ftp.sendcmd("TYPE I")
        except ftplib.all_errors:
            pass
        try:
            result["working_directory"] = ftp.pwd()
        except ftplib.all_errors as e:
            result["working_directory_error"] = str(e)

        for path in ("/etc/passwd", "/etc/shadow"):
            probe = {"visible": False}
            try:
                probe = {"visible": True, "size": ftp.size(path), "method": "SIZE"}
            except ftplib.all_errors as size_error:
                lines = []
                try:
                    ftp.retrlines(f"LIST {path}", lines.append)
                    probe = {"visible": bool(lines), "method": "LIST"}
                except ftplib.all_errors as list_error:
                    probe["detail"] = f"SIZE: {size_error}; LIST: {list_error}"
            result["metadata_probes"][path] = probe

        result["root_filesystem_exposed"] = any(
            probe.get("visible") for probe in result["metadata_probes"].values()
        )
        result["status"] = (
            "affected_exposure" if result["root_filesystem_exposed"]
            else "anonymous_login_without_root_metadata"
        )
    except ConnectionRefusedError as e:
        result["status"] = "closed"
        result["detail"] = str(e)
    except (socket.timeout, TimeoutError) as e:
        result["status"] = "inconclusive"
        result["detail"] = f"timeout: {e}"
    except ftplib.all_errors as e:
        result["status"] = "inconclusive"
        result["detail"] = str(e)
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()
    return result


def parse_tcf_hello(message):
    fields = message.split(b"\x00")
    if (len(fields) >= 4 and fields[0] == b"E" and
            fields[1] == b"Locator" and fields[2] == b"Hello"):
        try:
            services = json.loads(fields[3].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return services if isinstance(services, list) else None
    return None


def check_tcf(host, port, timeout):
    result = {
        "port": port,
        "connected": False,
        "hello_received": False,
        "dangerous_services": [],
        "affected_exposure": False,
        "status": "unknown",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        result["connected"] = True
        buf = b""
        while EOM not in buf and len(buf) <= 65536:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
        if EOM not in buf:
            result["status"] = "inconclusive"
            result["detail"] = "port accepted a connection but sent no complete TCF Hello"
            return result
        for message in buf.split(EOM):
            services = parse_tcf_hello(message)
            if services is not None:
                result["hello_received"] = True
                result["advertised_services"] = services
                result["dangerous_services"] = sorted(DANGEROUS_TCF_SERVICES.intersection(services))
                result["affected_exposure"] = bool(result["dangerous_services"])
                result["status"] = "affected_exposure" if result["affected_exposure"] else "tcf_without_dangerous_services"
                return result
        result["status"] = "inconclusive"
        result["detail"] = "received data was not a parseable TCF Locator.Hello"
    except ConnectionRefusedError as e:
        result["status"] = "closed"
        result["detail"] = str(e)
    except (socket.timeout, TimeoutError) as e:
        result["status"] = "inconclusive"
        result["detail"] = f"timeout: {e}"
    except OSError as e:
        result["status"] = "inconclusive"
        result["detail"] = str(e)
    finally:
        sock.close()
    return result


def print_human(host, results):
    print(f"Read-only X240 exposure check: {host}")
    ftp = results["ftp"]
    print(f"  FTP/{ftp['port']}: {ftp['status']}")
    if ftp["anonymous_login"]:
        print("    anonymous login accepted")
    for path, probe in ftp["metadata_probes"].items():
        if probe.get("visible"):
            print(f"    metadata visible: {path} ({probe.get('size')} bytes)")

    tcf = results["tcf"]
    print(f"  TCF/{tcf['port']}: {tcf['status']}")
    if tcf["dangerous_services"]:
        print(f"    dangerous services: {', '.join(tcf['dangerous_services'])}")

    if results["exposed"]:
        print("RESULT: affected exposure detected")
    elif results["inconclusive"]:
        print("RESULT: inconclusive; at least one service could not be assessed")
    else:
        print("RESULT: no affected exposure detected by these checks")


def main():
    ap = argparse.ArgumentParser(description="Read-only Frontline X240 exposure checker")
    ap.add_argument("host", nargs="?", default="10.10.0.240")
    ap.add_argument("--ftp-port", type=int, default=21)
    ap.add_argument("--tcf-port", type=int, default=1534)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true", help="print structured JSON")
    args = ap.parse_args()

    results = {
        "host": args.host,
        "read_only": True,
        "ftp": check_ftp(args.host, args.ftp_port, args.timeout),
        "tcf": check_tcf(args.host, args.tcf_port, args.timeout),
    }
    results["exposed"] = (
        results["ftp"]["root_filesystem_exposed"] or
        results["tcf"]["affected_exposure"]
    )
    results["inconclusive"] = any(
        check["status"] == "inconclusive" for check in (results["ftp"], results["tcf"])
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_human(args.host, results)
    sys.exit(1 if results["exposed"] else 2 if results["inconclusive"] else 0)


if __name__ == "__main__":
    main()
