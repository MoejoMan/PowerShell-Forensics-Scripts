# PowerShell Forensics Scripts

PowerShell scripts for collecting forensic data from Windows systems during live investigations. Built for the digital forensics course (SCI721), following ACPO guidelines and ISO standards.

## What It Does

Basically, these scripts automate the collection of evidence from a live Windows machine:
- RAM dumps (before the machine gets shut down)
- Running processes and what they're doing
- User accounts on the system
- Network connections (who's connected where)
- Prefetch files (what was run recently)
- Full disk imaging with FTK Imager
- HTML reports with all the findings

## Project Structure

```
├── main.ps1                    # Primary orchestrator script
├── functions.ps1               # Modular forensic functions
├── awesomescript.ps1           # Full-featured collection script (reference)
├── FTKImagerCLI.ps1            # Disk imaging via FTK Imager
├── MediumTierScript.ps1        # RAM dump + process collection
├── RAM_Winpmem.ps1             # WinPmem-based memory acquisition
├── RAM_DumpIt.ps1              # DumpIt-based memory acquisition
├── run.bat                      # Auto-elevating batch launcher
├── bin/                         # External tools (WinPmem, etc.)
├── Evidence/                    # Output directory for collected data
├── Transcript/                  # Execution logs (ACPO Principle 3 compliance)
└── ForensicImage/              # FTK Imager output
```

## Quick Start

## How to Use

Just run:
```powershell
.\run.bat
```

This handles admin elevation for you. Or if you want to run PowerShell directly:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "main.ps1"
```

Everything gets logged to the `Transcript/` folder with timestamps, and data gets saved as CSV files in `Evidence/`.

## Script Documentation

### main.ps1
Orchestrator script that imports and calls all modular functions:
- Calls `Get-ProcessList`
- Calls `Get-UserList`
- Calls `Get-PrefetchFiles`

### functions.ps1
**Modular forensic functions:**

- `Get-ProcessList` - Retrieves all running processes with CPU/memory data
- `Get-UserList` - Enumerates local user accounts
- `Get-PrefetchFiles` - Collects Windows prefetch files (execution timeline evidence)

### awesomescript.ps1
Complete forensic collection pipeline including:
- RAM dumping (WinPmem)
- Process collection (exported to CSV)
- User account enumeration
- TCP/UDP connection analysis
- Network neighbor (ARP) table capture
- Prefetch file acquisition
- Automated HTML report generation

### FTKImagerCLI.ps1
Disk imaging integration:
- Creates forensic images in E01 format
- Generates MD5/SHA1 hashes
- Verifies image integrity
- Supports case/evidence numbering

## PowerShell Cmdlets Used
| Cmdlet | Purpose |
|--------|---------|
| `Get-Process` | Running process enumeration |
| `Get-LocalUser` | User account discovery |
| `Get-ChildItem` | File system enumeration |
| `Get-NetTCPConnection` | Network connection analysis |
| `Start-Transcript` | Audit logging |
| `Export-Csv` | Data export for analysis |
| `ConvertTo-Html` | Report generation |

## What Gets Output

The scripts generate:
- **CSV files** - Easy to open in Excel or import into forensic tools
- **HTML reports** - For the actual submission/court
- **Transcript logs** - Everything that ran, with timestamps
- **E01 images** - Full disk images if using FTK Imager

Everything goes in the appropriate folder (`Evidence/`, `Transcript/`, `ForensicImage/`) so it's organized.

## The Assignment

For SCI721, we have to do a live forensic investigation on a VM, collect evidence properly, document everything, and write an expert report for court. This toolkit handles the automated collection part — grab the RAM, processes, network stuff, etc. before the machine gets turned off. Then you analyze what you collected.

## Usage Example

```powershell
# Import the functions
. .\functions.ps1

# Collect live system data
Get-ProcessList
Get-UserList
Get-PrefetchFiles

# Results displayed and logged to Transcript\ directory
```

## License

Educational use - ARU Digital Forensics Module
