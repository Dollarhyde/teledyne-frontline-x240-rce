# Unauthenticated remote code execution in Teledyne LeCroy Frontline wireless protocol analyzers

## Summary

This report documents two independent, unauthenticated remote code execution vulnerabilities in the Teledyne LeCroy Frontline family of wireless protocol analyzers. The first arises from a BusyBox FTP daemon that accepts anonymous logins while running with root privilege, granting arbitrary read and write access to the entire filesystem. The second arises from a Xilinx Target Communication Framework (TCF) debug agent that is left enabled in the shipped firmware and exposes a full debug service set, including arbitrary process creation, without authentication. The vendor rates the RCE condition Critical, with a CVSS v3.1 base score of 9.8. Both issues were reported under coordinated disclosure and are published here following the vendor advisories. 

## Affected products and versions

The vulnerabilities affect the Ethernet-capable members of the Frontline line, specifically the X240, X240i, X500, and X500e, together with the Voyager M480x on the USB Protocol Suite platform. The relevant software versions are Wireless Protocol Suite (WPS) 4.70 Alpha, 4.61 Alpha, and 4.60 GA, and USB Protocol Suite 10.00 through 10.30. Devices operated exclusively over USB are not exposed, because the affected services are bound to the Ethernet host interface. Corrected builds are available in WPS 4.70 Beta and later, and USB Protocol Suite 10.31 Beta and later.

## Device background

The Frontline X240 is a wireless protocol analyzer used to capture and decode Bluetooth and 802.15.4 traffic. In normal operation the capture host runs the Wireless Protocol Suite on Windows and communicates with the analyzer over USB or, when the host is remote, over Ethernet. The analyzer itself is built on a Xilinx Zynq platform running PetaLinux 2018.2 with a 4.14 aarch64 kernel. This detail is significant, because both vulnerabilities originate in development and manufacturing services that the PetaLinux board support package enables by default and that were not disabled prior to release.

## Reconnaissance

A full TCP service and version scan of the host interface returns four open ports. The relevant portion of the nmap output is reproduced below.

```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           BusyBox ftpd
22/tcp   open  ssh           Dropbear sshd 2017.75 (protocol 2.0)
23/tcp   open  telnet
1534/tcp open  micromuse-lm?
MAC Address: 00:10:4C:XX:XX:XX (Teledyne LeCroy; device suffix redacted)
```

The version probe incorrectly attributed the FTP banner to a D-Link network camera and could not identify the service on port 1534. The telnet banner discloses the platform directly, presenting a `PetaLinux 2018.2 x240` login prompt. The organizationally unique identifier of the MAC address confirms the hardware vendor. The two services of interest are the FTP daemon on port 21 and the unidentified service on port 1534.

## Vulnerability 1: anonymous FTP with root privilege

The service on port 21 is BusyBox `ftpd`. The scan indicated that anonymous authentication is permitted, returning FTP status code 230. Upon anonymous login the daemon places the session at the true filesystem root rather than within a restricted upload directory, and every listed entry is owned by `root:root`. BusyBox `ftpd` does not relinquish privilege on its own; the effective user of the served session is the user that launched the daemon, which in this firmware is uid 0.

Read access was verified by retrieving files that an anonymous peer has no legitimate basis to read. Both `/etc/passwd` and `/etc/shadow` were retrievable, the latter containing the root account's sha512crypt hash. Write access was verified by uploading a small marker file to `/tmp`, retrieving it, and confirming a byte-exact match, after which a directory listing showed the uploaded file owned by `root:root`. These observations together establish arbitrary read and write across the filesystem, performed as root, by an unauthenticated network peer.

Privilege escalation to an interactive session follows directly and without modifying any existing account. The `/etc/passwd` and `/etc/shadow` files are retrieved, a single line is appended to each to define an additional account with uid 0 and an attacker-controlled password hash, and both files are written back. The appended entries take the following form.

```
support:x:0:0:X240 Lab Access:/tmp:/bin/sh          (appended to /etc/passwd)
support:$6$...:18567:0:99999:7:::                    (appended to /etc/shadow)
```

Authentication as the new account then yields a root shell over SSH.

```
$ ssh support@10.10.0.240 -oHostKeyAlgorithms=+ssh-rsa
support@10.10.0.240's password:
root@x240:~# id
uid=0(root) gid=0(root)
```

Introducing a parallel uid-0 account, rather than altering the primary root entry, leaves the original credentials intact and produces no obvious change to the account that an administrator is most likely to inspect. The accompanying proof-of-concept tool (`poc/x240_ftp_adduser.py`) backs up both files before writing, requires explicit confirmation prior to upload, and emits the exact command needed to restore the originals, so that the device can be returned to its initial state. Because SSH and telnet are both exposed, the filesystem write is not strictly required to demonstrate impact, but it provides the most direct route to an interactive shell. The same write primitive reaches init scripts, the FPGA bitstream directory, and any other object on the disk.

## Vulnerability 2: unauthenticated Xilinx TCF debug agent

Immediately upon connection to port 1534, and before the client transmits anything, the service emits an unsolicited message announcing a set of services.

```
E Locator Hello ["ZeroCopy","Diagnostics","Profiler","Disassembly","DPrintf","Terminals","PathMap","Streams","Expressions","SysMonitor","FileSystem","ProcessesV1","Processes","LineNumbers","SymbolsProxyV2","SymbolsProxyV1","Symbols","StackTrace","Registers","MemoryMap","Memory","Breakpoints","RunControl","ContextQuery","Locator"]
```

This is the Eclipse Target Communication Framework, the protocol used by the Xilinx XSCT and Vitis toolchains to control a target during hardware bring-up. Its capabilities include setting breakpoints, reading and writing process memory and CPU registers, spawning processes, and reading and writing files. The agent implementing it, `tcf-agent`, is a development instrument with no legitimate role on a production appliance, and it enforces no authentication of any kind. Any peer able to reach the port is granted the complete service set shown above. The two services with the most direct consequence are `Processes`, which spawns an arbitrary executable, and `FileSystem`, which reads and writes arbitrary paths. Both operate in the agent's context, and the agent runs as root.

Establishing command dispatch required accounting for a detail of the protocol. Initial commands, including a benign `Locator.getAgentID`, consistently timed out while the connection remained open. The Service Locator specification requires both endpoints to exchange a `Locator.Hello` event when the channel opens, and the Xilinx agent will not dispatch any command from a peer that has not first announced itself. Once an empty client Hello is sent immediately after connecting, the agent begins responding normally.

```
client sends:  E Locator Hello []
```

For this reason, every command-capable TCF tool in this repository transmits a client Hello before issuing any command. With dispatch functioning, `Locator.getAgentID` returned a stable agent identifier (redacted here because it may identify the test unit), confirming a live command channel. Code execution is then achieved through a single call to the process-creation service.

```
ProcessesV1.start("/tmp", "/bin/sh", ["sh","-c","<command>"], [], {"Attach": False})
```

The agent invokes `execve` on the supplied program and returns the resulting process context. In the proof of concept the command writes a marker file, allowing the execution context to be verified independently from a separate login.

```
$ cat /var/volatile/tmp/x240_tcf_poc_1779895079.txt
=== TCF_POC_MARKER 1779895079 ===
Mon Nov  2 02:02:23 UTC 2020
uid=0(root) gid=0(root)
Linux x240 4.14.0-xilinx-v2018.2 #13 SMP aarch64 GNU/Linux
agent_pid=2221
ppid=2082
```

The `id` line confirms execution as uid 0. The parent process identifier corresponds to the `tcf-agent` process itself, establishing that the spawned shell is a direct child of the debug agent. The clock reading of November 2020 reflects the device's own system time; the unit has neither a real-time clock battery nor an NTP configuration, so its clock retains whatever value was set at boot. The timestamp is preserved here as a genuine artifact of the device rather than an artifact of testing.

Where persistent key-based access is preferred to single-command execution, the exposed TCF services can add a public key to the root account's `authorized_keys` file; this is implemented in `poc/x240_tcf_keyplant.py`. The tool preserves existing keys, makes a recovery backup when the file already exists, avoids adding a duplicate key, and records state for targeted cleanup or backup restoration.

## Root cause

Neither vulnerability involves memory corruption or a subtle protocol flaw. Both are development and manufacturing services that a standard Xilinx workflow enables, that run with root privilege, and that were not disabled before the product shipped. The FTP daemon exists so that the manufacturing process can transfer files to the unit. The TCF agent exists so that firmware engineers can attach a debugger during development. Both remain reachable, unauthenticated, and privileged on the same Ethernet interface that customers are directed to connect to their networks. The two findings are therefore best understood as a single class of defect, the retention of privileged development scaffolding in a release build, manifesting through two distinct services.

## Impact

Each vulnerability independently provides unauthenticated remote code execution as root. The vendor rates the RCE condition Critical, with a CVSS v3.1 base score of 9.8. An attacker with this level of access obtains the captured protocol data held on the device, the FPGA bitstream, and the stored account hashes, and can use the analyzer as a foothold onto any network segment it can reach. Because the analyzer is frequently connected to engineering and laboratory networks where sensitive prototype traffic is present, the practical consequences extend beyond the device itself.

## Disclosure timeline

- 2026-05-26: reconnaissance and testing conducted on the lab unit.
- 2026-05-27: both vulnerabilities reported to Teledyne LeCroy with proof-of-concept code and supporting evidence.
- Subsequent weeks: coordination with the vendor during reproduction and remediation.
- 2026-06-24: advisory TDY-PSG-2026-001 published, covering the Frontline products.
- 2026-06-25: advisory TDY-PSG-2026-002 published, covering the Voyager M480x.
- 2026-08-25: ninety-day coordinated-disclosure window concluded.
- 2026-10-04: publication of this report following the coordinated-disclosure window.

The vendor's handling of this disclosure was prompt and cooperative. 

## Remediation

Operators of affected devices should update to the corrected builds, WPS 4.70 Beta or later and USB Protocol Suite 10.31 Beta or later, and allow the accompanying firmware update to complete. Until the update can be applied, the Ethernet host interface should be kept off untrusted networks. Because the exposed services cannot authenticate a peer, network reachability is the sole precondition for exploitation, and an analyzer confined to a dedicated capture segment with no route to other systems presents a substantially lower risk than one attached to a general-purpose network.

## Availability

The proof-of-concept tools are located in `poc/`, one per capability, with accompanying usage notes in `poc/README.md`. Recorded demonstrations against the lab unit are provided in `media/`. The vendor advisories are included in `advisories/`. All code is released under the GNU General Public License v3.0. The disclaimer in `DISCLAIMER.md` should be read before any of the tools are used.
