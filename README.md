# PowerShell Forensics Toolkit

PowerShell scripts for automated forensic data collection from Windows systems during live investigations. Built for the ARU Digital Forensics module (SCI721), following ACPO Good Practice Guidelines, ISO 27037, and ISO 17025 standards.

## What It Does

This toolkit automates **55+ forensic collection functions** across 5 script files, running in order-of-volatility priority. It is designed for a two-VM crime scene: one sleeping/suspended VM (live triage + memory) and one switched-off VM (disk imaging for offline analysis).

### Collection Coverage

**Priority 1 - Volatile Data (RAM)**
- RAM dump via WinPmem or DumpIt (admin required)

**Priority 2 - System & Network Data**
- Running processes (PID, CPU, memory, path)
- System information (OS, hostname, timezone, uptime, Secure Boot, DeviceGuard, BitLocker)
- Local user accounts and last logon times
- TCP connections (local/remote/state)
- Network neighbors (ARP table)
- Prefetch files (execution timeline, admin required)
- Installed programs (Uninstall registry + Appx packages)
- Services (name, status, start type)
- Scheduled tasks (actions, authors, state)
- Network adapter configuration (IP/DNS/gateway)
- Autoruns (Run/RunOnce keys + Startup folders)
- Browser artifacts & downloads (Chrome/Edge/Firefox history DB copy)
- WMI persistence (event filters/consumers/bindings)

**Priority 2.5 - Full Event Logs**
- Full .evtx export (Security, System, Application) - all history
- Key event ID triage CSV (logon events, service installs, audit changes, etc.)

**Priority 3 - Anti-Forensics & Concealment Detection**
- Alternate Data Streams (NTFS ADS scanning)
- Hidden & system files in user-writable directories
- Encrypted volume/container detection (BitLocker, VeraCrypt, TrueCrypt)
- Volume Shadow Copy enumeration (missing = anti-forensic deletion)
- Timestomp detection (Created > Modified anomalies)
- Windows Defender exclusion audit (hidden malware paths)

**Priority 4 - File Provenance & User Activity**
- Zone.Identifier download origins (URL source for every download)
- Recent file activity / MRU lists (RecentDocs, TypedPaths, RunMRU)
- USB device history (USBSTOR registry - data exfiltration evidence)
- Recycle Bin contents + raw $R/$I file copies
- UserAssist program execution history (ROT13 decoded, run counts)
- Hosts file tampering detection
- Firewall rule analysis (inbound allow = backdoor indicators)

**Priority 4.5 - Deep-Dive Artifacts**
- WiFi profiles (saved networks with auth type)
- Desktop wallpaper info
- Browser bookmarks (Chrome/Edge/Firefox)
- Browser search query history
- Windows Activity Timeline (ActivitiesCache.db)
- Game & entertainment artifacts (Steam, Discord, etc.)

**Priority 5 - Volatile / Time-Sensitive**
- DNS client cache
- Clipboard text capture
- Mapped drives & SMB shares/sessions

**Priority 6 - Command History & Remote Access**
- PowerShell command history (PSReadLine per-user)
- RDP & remote session artifacts (recent servers, cache, active sessions)

**Priority 7 - Registry, Execution Evidence & File Metadata**
- Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat)
- SRUM database (network usage, app execution history)
- Amcache & ShimCache (execution evidence)
- LNK files & Jump Lists (file access history)
- Thumbnail cache (viewed images/videos)
- $MFT, $LogFile, $UsnJrnl:$J (file system timeline + deleted file recovery)

**Priority 8 - Email & Memory Files**
- Email artifacts (Outlook PST/OST, Thunderbird mbox, Windows Mail)
- EML/MSG standalone email file scanning
- Pagefile, hiberfil.sys, swapfile.sys acquisition

**Priority 9 - Targeted Investigation Scans**
- Extortion/theft keyword scanning (filenames + text content)

**Post-Collection**
- SHA256 hashing of all evidence files (chain of custody integrity)
- Memory analysis via Volatility 3 + strings.exe (on RAM dump and sleeping VM .vmem)
- HTML report generation with case metadata, ACPO banner, and red flags summary
- VM image acquisition loop (sleeping VM + switched-off VM from host)

## Project Structure

```
main.ps1                        # Primary orchestrator script
functions.ps1                   # Core forensic functions (45+ functions)
advanced_functions.ps1           # Registry, SRUM, Amcache, LNK, MFT, FTK, sleeping VM
new_functions.ps1                # Full event logs + multi-VM batch mode
email_pagefile_functions.ps1     # Email artefacts + pagefile/hiberfil collection
run.bat                         # Auto-elevating batch launcher
bin/                            # External tools
    FTKImager/                  #   FTK Imager CLI (VMDK/disk imaging)
    PowerForensicsv2/           #   PowerForensics module ($MFT, $LogFile, etc.)
    Strings/                    #   SysInternals strings.exe/strings64.exe
    volatility3/                #   Volatility 3 source (requires Python)
    winpmem/                    #   WinPmem RAM acquisition driver
Evidence/<label>/               # Output directory for collected data
HTMLReport/<label>/             # HTML report output
Transcript/<label>/             # Execution transcript logs (ACPO Principle 3)
Archive/                        # Local archive of previous runs (git-ignored)
```

## How to Use

### Quick start
```
run.bat
```
This handles admin elevation automatically via UAC.

### With a VM label (keeps evidence separated per machine)
```
run.bat -VmLabel VM1_Live
run.bat -VmLabel VM2_Sleeping
```
Outputs land in `Evidence/VM1_Live/`, `HTMLReport/VM1_Live/`, etc.

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

### Two-VM Crime Scene Workflow
On the day (Feb 28), the expected workflow is:

1. **Start on the sleeping VM** - wake it from sleep, run the full toolkit as admin:
   ```
   run.bat -VmLabel VM1_Sleeping
   ```
   This captures live RAM, processes, network connections, and all non-volatile artifacts.

2. **After collection completes**, the script prompts for VM image acquisition:
   - Image the sleeping VM VMDK (creates E01 forensic image + copies .vmem)
   - Volatility + strings analysis runs automatically on the .vmem
   - Then image the switched-off VM VMDK (disk-only, no memory)

3. **All evidence is separated** by label under `Evidence/`, `HTMLReport/`, `Transcript/`.

## Script Documentation

### main.ps1
Orchestrator script. Dot-sources all 4 function files, runs collectors in order-of-volatility (Priorities 1-9), generates HTML report, then enters the VM image acquisition loop. Includes ACPO compliance banner at transcript start.

### functions.ps1
Core forensic function library containing 47 functions:

| Function | Purpose |
|----------|---------|
| `Export-MemoryDump` | RAM acquisition via WinPmem/DumpIt |
| `Get-ProcessList` | Running processes with CPU/memory/path |
| `Get-SystemInfo` | OS, hostname, timezone, uptime, Secure Boot, DeviceGuard, BitLocker |
| `Get-UserList` | Local user accounts and last logon |
| `Get-NetworkConnections` | TCP connections (local/remote/state) |
| `Get-NetworkNeighbors` | ARP table / network neighbors |
| `Get-PrefetchFiles` | Windows prefetch (execution timeline) |
| `Get-InstalledPrograms` | Uninstall registry + Appx packages |
| `Get-ServicesList` | All Windows services with start type |
| `Get-ScheduledTasksList` | Scheduled tasks with actions/authors |
| `Get-NetworkConfig` | Adapter configuration (IP/DNS/gateway) |
| `Get-Autoruns` | Run/RunOnce keys + startup folders |
| `Get-BrowserArtifactsAndDownloads` | Downloads + Chrome/Edge/Firefox history DB copy |
| `Get-WmiPersistence` | WMI event filters/consumers/bindings |
| `Get-AlternateDataStreams` | NTFS ADS scan (hidden data) |
| `Get-HiddenFiles` | Hidden/system files in user-writable dirs |
| `Get-EncryptedVolumeDetection` | BitLocker, VeraCrypt, TrueCrypt containers |
| `Get-ZoneIdentifierInfo` | Download origin URLs (Zone.Identifier ADS) |
| `Get-RecentFileActivity` | RecentDocs, TypedPaths, RunMRU registry |
| `Get-USBDeviceHistory` | USBSTOR registry + mounted removable drives |
| `Get-RecycleBinContents` | Deleted files + raw $R/$I copies |
| `Get-DNSCache` | DNS client cache (volatile) |
| `Get-ClipboardContents` | Current clipboard text (volatile) |
| `Get-MappedDrivesAndShares` | Mapped drives, SMB shares, active sessions |
| `Get-PowerShellHistory` | PSReadLine ConsoleHost_history per user |
| `Get-RDPAndRemoteSessions` | RDP recent servers, cache, active sessions |
| `Get-MemoryStrings` | Volatility 3 + strings.exe analysis on RAM/.vmem |
| `Get-ShadowCopies` | Volume Shadow Copy enumeration |
| `Get-TimestompDetection` | Created > Modified anomaly detection |
| `Get-UserAssistHistory` | ROT13-decoded UserAssist program execution |
| `Get-HostsFileCheck` | Hosts file tampering detection |
| `Get-FirewallRules` | Inbound allow firewall rules |
| `Get-DefenderExclusions` | Windows Defender exclusion audit |
| `Get-WiFiProfiles` | Saved WiFi networks |
| `Get-WallpaperInfo` | Desktop wallpaper metadata |
| `Get-BrowserBookmarks` | Chrome/Edge/Firefox bookmarks |
| `Get-BrowserSearchHistory` | Browser search query extraction |
| `Get-WindowsTimeline` | Windows Activity Timeline |
| `Get-GameArtifacts` | Steam, Discord, game artifacts |
| `Get-EmlMsgFiles` | Standalone .eml/.msg email file scanner |
| `Search-ExtortionIndicators` | Extortion/theft keyword scanner (Criterion B) |
| `Get-FileHashes` | SHA256 hashes of output files |
| `New-HTMLReport` | HTML report with case metadata, ACPO banner, red flags |

### advanced_functions.ps1
Advanced artifact collection (8 functions):

| Function | Purpose |
|----------|---------|
| `Get-RegistryHives` | SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat |
| `Get-SRUMDatabase` | SRUM database (network usage, app execution) |
| `Get-AmcacheAndShimcache` | Amcache.hve + ShimCache extraction |
| `Get-LnkAndJumpLists` | LNK files + Jump Lists (auto/custom destinations) |
| `Get-ThumbnailCache` | Thumbcache DB files (viewed images/videos) |
| `Get-MFTAndUsnJournal` | $MFT, $LogFile, $UsnJrnl:$J acquisition |
| `Get-FTKImage` | FTK Imager CLI integration (E01/RAW imaging) |
| `Get-SleepingVMArtefacts` | Sleeping VM workflow (VMDK search, .vmem copy, FTK imaging) |

### email_pagefile_functions.ps1
Email and memory file collection (2 functions):

| Function | Purpose |
|----------|---------|
| `Get-EmailArtefacts` | Outlook PST/OST, Thunderbird mbox, Windows Mail |
| `Get-PagefileAndHiberfil` | pagefile.sys, hiberfil.sys, swapfile.sys acquisition |

### new_functions.ps1
Event log export and multi-VM orchestration (2 functions):

| Function | Purpose |
|----------|---------|
| `Get-FullEventLogs` | Full .evtx export + key event ID triage CSV |
| `Invoke-MultiVMCollection` | Multi-VM batch mode orchestrator |

### run.bat
Auto-elevating batch launcher. Requests admin via UAC if not already elevated. Passes all arguments through to main.ps1 (e.g. `-VmLabel`, `-SkipRamDump`). Includes `pause` at end so the window stays open.

## What Gets Output

| Output | Location | Format |
|--------|----------|--------|
| Evidence CSVs | `Evidence/<label>/` | CSV |
| Browser DB copies | `Evidence/<label>/browser_artifacts/` | SQLite |
| Event log exports | `Evidence/<label>/evtx/` | .evtx + triage CSV |
| Registry hives | `Evidence/<label>/registry_hives/` | .hiv |
| LNK / Jump Lists | `Evidence/<label>/lnk_jumplists/` | Binary |
| Thumbnail cache | `Evidence/<label>/thumbnail_cache/` | Binary |
| MFT / USN | `Evidence/<label>/mft_usn/` | Binary |
| Email artefacts | `Evidence/<label>/email_artefacts/` | PST/OST/mbox |
| EML/MSG files | `Evidence/<label>/email_files/` | .eml/.msg |
| Memory files | `Evidence/<label>/memory_files/` | Binary |
| Memory analysis | `Evidence/<label>/memory_analysis/` | Text + CSV |
| Recycle Bin files | `Evidence/<label>/recycle_bin_files/` | Mixed |
| HTML report | `HTMLReport/<label>/forensic_report.html` | HTML |
| Transcript logs | `Transcript/<label>/` | Text log |
| RAM dump | `Evidence/<label>/` | Raw memory image |
| File hashes | `Evidence/<label>/hashes.csv` | CSV (SHA256) |
| Image hashes | `Evidence/<label>/image_hashes.csv` | CSV (MD5+SHA1+SHA256) |
| Extortion indicators | `Evidence/<label>/extortion_indicators.csv` | CSV |

## Standards Compliance

- **ACPO Good Practice Guidelines** - 4 principles logged in transcript + HTML report
- **ISO 27037** - Digital evidence identification, collection, acquisition, preservation
- **ISO 17025** - Forensic laboratory competence
- **Forensic Science Regulator** - Code of Practice compliance
- **SHA256 hashing** of all evidence files for chain of custody integrity
- **Full transcript logging** of all actions (ACPO Principle 3 audit trail)

## Notes

- Run as **administrator** for full collection (RAM, prefetch, security logs, SRUM, $MFT, registry hives).
- WinPmem must be in `bin\winpmem\` for RAM capture.
- FTK Imager CLI must be in `bin\FTKImager\` for VMDK imaging.
- Volatility 3 requires Python in PATH (source in `bin\volatility3\`).
- Each `-VmLabel` gets its own output tree - multi-machine evidence stays separated.
- The VM acquisition loop supports imaging multiple VMs sequentially from the host.

## License

Educational use - ARU Digital Forensics Module (SCI721)