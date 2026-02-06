# PowerShell Forensics Scripts

A modular PowerShell-based forensic data collection toolkit for live investigation of Windows systems. Designed to comply with ACPO (Association of Chief Police Officers) good practice guidelines and ISO 27037 standards.

## Purpose

This project provides automated PowerShell scripts to acquire forensic evidence from Windows machines during live investigations, including:
- **Live system memory dumps** (RAM acquisition)
- **Running process enumeration** and analysis
- **User account auditing**
- **Network connection monitoring** (TCP/UDP connections, ARP tables)
- **Prefetch file collection** (execution history)
- **Disk imaging** via FTK Imager CLI integration
- **Automated HTML report generation** for court documentation

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

### Prerequisites
- Windows PowerShell 5.0+
- Administrator privileges
- FTK Imager (optional, for disk imaging)
- WinPmem or DumpIt (optional, for advanced RAM acquisition)

### Basic Usage

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/MoejoMan/PowerShell-Forensics-Scripts.git
   cd PowerShell-Forensics-Scripts
   ```

2. **Run the main script:**
   ```powershell
   .\run.bat
   ```
   This will auto-elevate to administrator if needed.

3. **Or run main.ps1 directly:**
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File "main.ps1"
   ```

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

## Key Concepts

### Compliance
- **ACPO Principle 3:** All actions logged via `Start-Transcript` for audit trail
- **Chain of Custody:** Scripts generate timestamped logs and hash verification
- **Non-destructive:** Live investigation designed to minimize system modification

### PowerShell Cmdlets Used
| Cmdlet | Purpose |
|--------|---------|
| `Get-Process` | Running process enumeration |
| `Get-LocalUser` | User account discovery |
| `Get-ChildItem` | File system enumeration |
| `Get-NetTCPConnection` | Network connection analysis |
| `Start-Transcript` | Audit logging |
| `Export-Csv` | Data export for analysis |
| `ConvertTo-Html` | Report generation |

### Data Output Formats
- **CSV files** - Importable to Excel, forensic tools
- **HTML reports** - Court-ready documentation with collapsible sections
- **Transcript logs** - Full execution history with timestamps
- **E01 images** - Forensic imaging via FTK Imager

## Assessment Context

This project supports a live forensic investigation assessment (ARU SCI721) requiring:
1. Evidence intake and chain of custody documentation
2. Forensic report detailing exhibits and findings
3. Expert witness statement with contemporaneous notes
4. Court-ready documentation bundle

**Note:** Scripts must be well-commented and all outputs (transcripts, HTML reports, CSV exports) must be included in final submission.

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

## Important Reminders

- **Always run as Administrator** (run.bat handles this automatically)
- **Test on non-production systems first**
- **Maintain chain of custody** - All logs are timestamped
- **Verify hashes** - Disk images include MD5/SHA1 verification
- **Document everything** - Contemporaneous notes required for court

## License

Educational use - ARU Digital Forensics Module

## Author

Created for SCI721 Digital Forensics Investigation Module
