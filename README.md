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
- TCP connections
- Network neighbors (ARP)
- Network adapter configuration
- Prefetch files
- HTML report summary of results

## Project Structure

```
├── main.ps1                    # Primary orchestrator script
├── functions.ps1               # Modular forensic functions
├── run.bat                     # Auto-elevating batch launcher
├── bin/                         # External tools (WinPmem, etc.)
├── Evidence/                    # Output directory for collected data
├── HTMLReport/                  # HTML report output
└── Transcript/                  # Execution logs (ACPO Principle 3 compliance)
```

## How to Use

Just run:
```powershell
.\run.bat
```

This handles admin elevation for you. Or if you want to run PowerShell directly:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "main.ps1"
```

Optional switches:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -SkipRamDump
powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -SkipHashes
```

Optional environment variables:
```powershell
$env:SKIP_RAM_DUMP = "1"
$env:SKIP_HASHES = "1"
```

Everything gets logged to the `Transcript/` folder with timestamps, and data gets saved as CSV files in `Evidence/`.

## Script Documentation

### main.ps1
Orchestrator script that imports and calls all modular functions:
- Calls `Get-ProcessList`
- Calls `Get-UserList`
- Calls `Get-PrefetchFiles`
- Calls `Export-MemoryDump`

### functions.ps1
**Modular forensic functions:**

- `Export-MemoryDump` - Acquires RAM via WinPmem (admin required)
- `Get-ProcessList` - Retrieves all running processes with CPU/memory data
- `Get-UserList` - Enumerates local user accounts
- `Get-PrefetchFiles` - Collects Windows prefetch files (execution timeline evidence)
- `Get-NetworkConnections` - Captures TCP connections
- `Get-NetworkNeighbors` - Captures ARP table
- `New-HTMLReport` - Builds the HTML summary report
- `Get-FileHashes` - Computes SHA256 hashes for output integrity

## Notes

- WinPmem must be present in `bin\winpmem\` or the project root.
- HTML and CSV outputs are generated on each run in `HTMLReport\` and `Evidence\`.
- Hashes are stored in `Evidence\hashes.csv`.

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
- **RAM dumps** - Raw memory image if WinPmem succeeds
- **Hashes** - SHA256 hashes of output files for integrity

Everything goes in the appropriate folder (`Evidence/`, `Transcript/`, `HTMLReport/`) so it's organized.

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
