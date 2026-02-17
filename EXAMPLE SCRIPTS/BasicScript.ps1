# Lists running processes, a list of prefetch files and user accounts

# Start transcript in script directory
$TranscriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $TranscriptPath -NoClobber

# Get running processes
Write-Output "=== Running Processes ==="
Get-Process | Format-Table -AutoSize

# List prefetch files
Write-Output "=== Prefetch Files ==="
Get-ChildItem "C:\Windows\Prefetch\*" -ErrorAction SilentlyContinue | Format-Table

# Get local user accounts
Write-Output "=== Local User Accounts ==="
Get-LocalUser | Format-Table -AutoSize

# Stop transcript and show location
Stop-Transcript
Write-Output "=== Transcript saved to: $TranscriptPath ==="