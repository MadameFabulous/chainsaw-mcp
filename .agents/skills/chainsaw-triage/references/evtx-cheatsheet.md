# Windows event IDs worth knowing during triage

| Channel | ID | Meaning | Why it matters |
|---|---|---|---|
| Security | 4624 | Logon | Type 3 network, 9 NewCredentials (runas /netonly, overpass-the-hash), 10 RDP |
| Security | 4625 | Failed logon | Sprays: many accounts, one source |
| Security | 4648 | Explicit credentials | Lateral movement with alternate creds |
| Security | 4672 | Special privileges assigned | Admin logons; pair with 4624 |
| Security | 4688 | Process creation | Only if command-line auditing enabled |
| Security | 4697 / System 7045 | Service installed | PsExec, persistence |
| Security | 4698/4702 | Scheduled task created/updated | Persistence |
| Security | 4720/4728/4732 | User created / added to group | Persistence, privilege escalation |
| Security | 4768/4769/4771 | Kerberos TGT/TGS/pre-auth failure | Kerberoasting (RC4 0x17 TGS), AS-REP roasting |
| Security | 4776 | NTLM authentication | Pass-the-hash context |
| Security | 4794 | DSRM password set | Domain persistence |
| Security | 5140/5145 | Share accessed / detailed | ADMIN$, C$, IPC$ lateral movement |
| Security | 1102 | Audit log cleared | Anti-forensics |
| System | 104 | Event log cleared | Anti-forensics |
| Sysmon | 1 | Process create | Full command line, hashes, parent |
| Sysmon | 3 | Network connection | Beacons, lateral movement |
| Sysmon | 7 | Image loaded | DLL side-loading, credential providers |
| Sysmon | 8 | CreateRemoteThread | Injection |
| Sysmon | 10 | Process access | LSASS access (0x1010, 0x1fffff) |
| Sysmon | 11 | File create | Dropped tools |
| Sysmon | 12/13 | Registry | Run keys, service configs |
| Sysmon | 17/18 | Named pipes | Cobalt Strike, PsExec |
| Sysmon | 22 | DNS query | C2 domains |
| PowerShell/Operational | 4104 | Script block | Deobfuscated content |
| PowerShell/Operational | 4103 | Module logging | Cmdlet invocations |
| Windows PowerShell | 400/403 | Engine start/stop | Downgrade to v2 |
| TaskScheduler/Operational | 106/140/200 | Task registered/updated/run | Persistence |
| RDP LocalSessionManager | 21/24/25 | Logon/disconnect/reconnect | Interactive lateral movement |
| WMI-Activity/Operational | 5857-5861 | WMI providers/consumers | Persistence, lateral movement |
| Defender/Operational | 1116/1117 | Malware detected/action | Tool drops |

Chainsaw rule groups (bundled `rules/evtx/`): account tampering, antivirus, credential
access, defence evasion, indicator removal, lateral movement, log tampering, login
attacks, microsoft rds events, persistence, powershell, rdp, service tampering,
service installation, and more. `chainsaw_get_rule(kind="chainsaw", path="evtx")` lists them.
