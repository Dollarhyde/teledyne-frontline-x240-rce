# Teledyne LeCroy Frontline X240 RCE

Two independent remote-code-execution (RCE) vulnerabilities in the Teledyne LeCroy Frontline wireless protocol analyzer line, reachable over the Ethernet host interface.

Both were reported to Teledyne LeCroy, patched, and disclosed in vendor advisories that credit the reporter. This repository is published after the patch and after a ninety-day window.

## Identified vulnerabilities

1. Anonymous FTP as root. BusyBox `ftpd` on TCP/21 accepts anonymous logins and runs as uid 0, giving arbitrary read and write across the whole filesystem. Append a uid-0 account to `/etc/passwd` and `/etc/shadow`, then log in over SSH or telnet.

2. Unauthenticated Xilinx TCF debug agent. The Xilinx `tcf-agent` on TCP/1534 runs as root with no authentication and exposes the full debug service set, including process spawn, arbitrary file read and write, and memory and register access. One `ProcessesV1.start` call gives a root shell.

The vendor rates the RCE condition Critical, with a CVSS v3.1 base score of 9.8. Full technical detail is in [`writeup.md`](writeup.md).

## Demonstrations

Recorded against an unpatched lab unit at 10.10.0.240.

Reconnaissance and detection: an nmap sweep, the read-only exposure checker, and a full enumeration of the TCF debug agent.

![Reconnaissance and detection](media/recon.gif)

An interactive root shell over the TCF debug agent, driven entirely over TCP/1534 with no authentication.

![Root shell over the TCF agent](media/tcf_rce.gif)

Anonymous FTP write used to add a uid-0 account, an interactive SSH login as root, then a clean restore of the original files.

![Anonymous FTP to interactive root](media/ftp_root_rce.gif)

## Affected products

Frontline X240, X240i, X500, X500e, and the Voyager M480x (USB Protocol Suite). WPS 4.70 Alpha, 4.61 Alpha, 4.60 GA, and USB Protocol Suite 10.00 through 10.30. Units operated only over USB are not affected, because the vulnerable services are on the Ethernet host interface.

Patched in WPS 4.70 Beta (or newer) and USB Protocol Suite 10.31 Beta (or newer).

## Layout

```
writeup.md      full technical writeup
poc/            proof-of-concept scripts, one per capability (see poc/README.md)
media/          recorded demonstrations (GIF)
advisories/     the two Teledyne LeCroy advisories (PDF)
DISCLAIMER.md   coordinated-disclosure and authorized-use notice
LICENSE         GPLv3
```

## Requirements

The tools require Python 3.9 or newer. Install the two non-standard dependencies used for password hashing and SSH key generation with:

```sh
python -m pip install -r requirements.txt
```

## Read-only exposure check

`poc/x240_check.py` checks for anonymous root-filesystem metadata exposure and the unsolicited TCF service announcement. It does not retrieve file contents, send TCF commands, start processes, or modify the target.

```sh
python poc/x240_check.py 10.10.0.240
python poc/x240_check.py 10.10.0.240 --json
```

## Vendor advisories

- TDY-PSG-2026-001 (Frontline): `advisories/TDY-PSG-2026-001.pdf`
- TDY-PSG-2026-002 (Voyager M480x): `advisories/TDY-PSG-2026-002.pdf`
- Teledyne LeCroy PSIRT: https://www.teledyne.com/en-us/psirt/Pages/default.aspx

## Use responsibly

The PoC code is for testing devices you own or are authorized to test. See [`DISCLAIMER.md`](DISCLAIMER.md). Reported under coordinated disclosure; published so operators can understand the risk and confirm they are patched.
