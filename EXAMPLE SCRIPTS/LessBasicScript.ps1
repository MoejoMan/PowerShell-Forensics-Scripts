# Bypass execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Start transcript
$TranscriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $TranscriptPath

# Get running processes
Write-Output "=== Running Processes ==="
Get-Process | Format-Table -AutoSize

# Copy prefetch files using Robocopy
Write-Output "=== Copying Prefetch Files ==="
$PrefetchFolder = "$PSScriptRoot\PrefetchCopy"
New-Item -ItemType Directory -Force -Path $PrefetchFolder | Out-Null

robocopy "C:\Windows\Prefetch" $PrefetchFolder /COPY:DAT /R:2 /W:5 /NP /NFL /NDL

# Get local user accounts
Write-Output "=== Local User Accounts ==="
Get-LocalUser | Format-Table -AutoSize

# Cleanup
Stop-Transcript
Write-Output "=== Transcript: $TranscriptPath ==="
Write-Output "=== Prefetch Copies: $PrefetchFolder ==="