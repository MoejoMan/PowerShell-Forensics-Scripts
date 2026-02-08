# PowerShell Forensics Scripts (WIP)

PowerShell scripts for collecting forensic data from Windows systems during live investigations. Built for the digital forensics course (SCI721), following ACPO guidelines and ISO standards. **Work in progress:** still evolving collection coverage and reporting.

## What It Does

This toolkit automates a focused set of live-collection tasks on Windows:
- RAM dump (via WinPmem, requires admin)
- Running processes
- Local user accounts
- Installed programs (Uninstall keys + Appx)
- Services
- Scheduled tasks
- Autoruns (Run/RunOnce, Startup folders)
- TCP connections
- Network neighbors (ARP)
- Network adapter configuration
- Prefetch files
- Downloads listing + best-effort browser history DB copy (Chrome/Edge)
- Event log triage (Security/System/Application, recent days)
- WMI persistence survey (filters/consumers/bindings)
- Alternate Data Stream (ADS) scanning — hidden data in NTFS
- Hidden & system file detection in user-writable directories
- Encrypted volume / container detection (BitLocker, VeraCrypt, TrueCrypt)
- Zone.Identifier download origin tracking (URL source for every downloaded file)
- Recent file activity / MRU lists (RecentDocs, TypedPaths, RunMRU)
- USB device history (USBSTOR registry — evidence of data exfiltration)
- Recycle Bin contents (deleted files the suspect tried to destroy)
- DNS client cache (volatile — domains recently resolved)
- Clipboard text capture (volatile — passwords, bitcoin addresses, etc.)
- Mapped drives & SMB shares (network shares, inbound sessions)
- PowerShell command history (PSReadLine per-user ConsoleHost_history.txt)
- RDP & remote session artifacts (recent servers, cache files, active sessions)
- Memory dump analysis note (with Volatility / strings.exe commands for offline work)
- HTML report summary of results

## Project Structure

```
├── main.ps1                    # Primary orchestrator script
├── functions.ps1               # Modular forensic functions
├── run.bat                     # Auto-elevating batch launcher (passes args)
├── bin/                         # External tools (WinPmem, etc.)
├── Evidence/<label>/            # Output directory for collected data
├── HTMLReport/<label>/          # HTML report output
├── Transcript/<label>/          # Execution logs (ACPO Principle 3 compliance)
└── Archive/                     # Local archive of previous runs (git-ignored)
```

## How to Use

### Quick start
```
run.bat
```
This handles admin elevation automatically.

### With a VM label (keeps evidence separated per machine)
```
run.bat -VmLabel VM1
run.bat -VmLabel HOST
```
Outputs land in `Evidence/VM1/`, `HTMLReport/VM1/`, etc.

### Skip options
```
run.bat -SkipRamDump
run.bat -SkipHashes
run.bat -VmLabel VM2 -SkipRamDump
```

### Direct PowerShell (no batch file)
```powershell
powershell.exe -ExecutionPolicy Bypass -File "main.ps1"
powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -VmLabel "VM1" -SkipRamDump
```

### Environment variables (alternative)
```powershell
$env:SKIP_RAM_DUMP = "1"
$env:SKIP_HASHES = "1"
```

## Script Documentation

### main.ps1
Orchestrator script that imports `functions.ps1` and runs every collector in order-of-volatility:
1. RAM capture (volatile, Priority 1)
2. Processes, users, TCP, ARP (volatile/semi-volatile)
3. Prefetch, installed programs, services, tasks, network config (non-volatile)
4. Autoruns, browser artifacts, downloads (persistence/user activity)
5. Event log triage (Security/System/Application, last 3 days)
6. WMI persistence survey (filters/consumers/bindings)
7. Anti-forensics scan: ADS, hidden files, encrypted volumes
8. File provenance: Zone.Identifier origins, recent file activity, USB history, Recycle Bin
9. Volatile capture: DNS cache, clipboard, mapped drives/shares
10. Command history & remote access: PowerShell history, RDP sessions
11. SHA256 hashing of all output files (integrity)
12. Memory dump analysis note (recommends Volatility / strings.exe for offline analysis)
13. HTML report generation

### functions.ps1
**Modular forensic functions (27 total):**

| Function | Purpose |
|----------|---------|
| `Export-MemoryDump` | Acquires RAM via WinPmem (admin required) |
| `Get-ProcessList` | Running processes with CPU/memory/path |
| `Get-UserList` | Local user accounts and last logon |
| `Get-NetworkConnections` | TCP connections (local/remote/state) |
| `Get-NetworkNeighbors` | ARP table / network neighbors |
| `Get-PrefetchFiles` | Windows prefetch (execution timeline) |
| `Get-InstalledPrograms` | Uninstall registry + Appx packages |
| `Get-ServicesList` | All Windows services with start type |
| `Get-ScheduledTasksList` | Scheduled tasks with actions/authors |
| `Get-NetworkConfig` | Adapter configuration (IP/DNS/gateway) |
| `Get-Autoruns` | Run/RunOnce keys + startup folders |
| `Get-BrowserArtifactsAndDownloads` | Downloads listing + Chrome/Edge history copy |
| `Get-EventLogTriage` | Recent Security/System/Application events |
| `Get-WmiPersistence` | WMI event filters/consumers/bindings |
| `Get-AlternateDataStreams` | NTFS ADS scan (hidden data on files) |
| `Get-HiddenFiles` | Hidden/system files in user-writable dirs |
| `Get-EncryptedVolumeDetection` | BitLocker, VeraCrypt, TrueCrypt containers |
| `Get-ZoneIdentifierInfo` | Download origin URLs (Zone.Identifier ADS) |
| `Get-RecentFileActivity` | RecentDocs, TypedPaths, RunMRU registry |
| `Get-USBDeviceHistory` | USBSTOR registry + mounted removable drives |
| `Get-RecycleBinContents` | Deleted files in Recycle Bin |
| `Get-DNSCache` | DNS client cache (volatile) |
| `Get-ClipboardContents` | Current clipboard text (volatile) |
| `Get-MappedDrivesAndShares` | Mapped drives, SMB shares, active sessions |
| `Get-PowerShellHistory` | PSReadLine ConsoleHost_history per user |
| `Get-RDPAndRemoteSessions` | RDP recent servers, cache, active sessions |
| `Get-MemoryStrings` | Logs RAM dump details + Volatility usage note |
| `Get-FileHashes` | SHA256 hashes of output files |
| `New-HTMLReport` | Builds the HTML summary report |

### run.bat
Auto-elevating batch launcher. Requests admin via UAC if not already elevated. Passes all arguments through to `main.ps1` (e.g. `-VmLabel`, `-SkipRamDump`).

## PowerShell Cmdlets Used
| Cmdlet | Purpose |
|--------|---------|
| `Get-Process` | Running process enumeration |
| `Get-LocalUser` | User account discovery |
| `Get-ChildItem` | File system enumeration (prefetch, downloads, hidden files) |
| `Get-NetTCPConnection` | TCP connection snapshot |
| `Get-NetNeighbor` | ARP / neighbor table |
| `Get-NetIPConfiguration` | Network adapter configuration |
| `Get-ItemProperty` | Registry queries (autoruns, installed programs, USB, RDP, MRU) |
| `Get-Service` | Windows service enumeration |
| `Get-ScheduledTask` | Scheduled task enumeration |
| `Get-AppxPackage` | UWP/Appx package listing |
| `Get-WinEvent` | Event log triage (with `-FilterHashtable`) |
| `Get-WmiObject` | WMI persistence survey, USB removable drives |
| `Get-FileHash` | SHA256 integrity hashing |
| `Get-Item -Stream` | NTFS Alternate Data Stream detection |
| `Get-Content -Stream Zone.Identifier` | Download origin / provenance tracking |
| `Get-BitLockerVolume` | Encrypted volume detection |
| `Get-DnsClientCache` | DNS cache (volatile) |
| `Get-PSDrive` | Mapped network drives |
| `Get-SmbShare` | SMB shares hosted locally |
| `Get-SmbSession` | Active inbound SMB sessions |
| `Start-Transcript` | Audit logging |
| `Export-Csv` | Data export for analysis tools |
| `ConvertTo-Html` | HTML report generation |

## What Gets Output

| Output | Location | Format |
|--------|----------|--------|
| Evidence CSVs | `Evidence/<label>/` | CSV (Excel/forensic tool import) |
| Browser DB copies | `Evidence/<label>/browser_artifacts/` | SQLite |
| HTML report | `HTMLReport/<label>/forensic_report.html` | HTML |
| Transcript logs | `Transcript/<label>/` | Text log |
| RAM dump | `Evidence/<label>/` | Raw memory image |
| File hashes | `Evidence/<label>/hashes.csv` | CSV (SHA256) |
| Clipboard capture | `Evidence/<label>/clipboard.txt` | Text |
| PS history copies | `Evidence/<label>/ps_history_<user>.txt` | Text |
| Memory IOCs | `Evidence/<label>/memory_strings.csv` | CSV |

All outputs are git-ignored. Previous runs can be found in `Archive/` (also ignored).

## Notes

- WinPmem must be present in `bin\winpmem\` or the project root.
- Run as administrator for full collection (RAM, prefetch, security logs).
- Event logs use `FilterHashtable` for performance — only pulls events from the last 3 days.
- Hashing covers all output files including browser artifact subdirectory.
- Each `-VmLabel` gets its own output tree so multi-machine evidence stays separated.

## The Assignment

For SCI721, we have to do a live forensic investigation on a VM, collect evidence properly, document everything, and write an expert report for court. This toolkit handles the automated collection part — grab the RAM, processes, network stuff, etc. before the machine gets turned off. Then you analyze what you collected.

## License

Educational use - ARU Digital Forensics Module
