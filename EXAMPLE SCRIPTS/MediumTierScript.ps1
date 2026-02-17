# Bypass Execution Policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Start Transcript
$TranscriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $TranscriptPath

# Dump RAM with DumpIt
Write-Output "=== Dumping RAM ==="
& "$PSScriptRoot\DumpIt.exe" /quiet /accepteula

# Get processes
Write-Output "=== Running Processes ==="
Get-Process | Format-Table -AutoSize

# Prefetch Files Grabbing
Write-Output "=== Copying Prefetch Files ==="
$PrefetchFolder = "$PSScriptRoot\PrefetchCopy"
New-Item -ItemType Directory -Force -Path $PrefetchFolder | Out-Null
robocopy "C:\Windows\Prefetch" $PrefetchFolder /COPY:DAT /R:2 /W:5 /NP /NFL /NDL

# Get users
Write-Output "=== Local User Accounts ==="
Get-LocalUser | Format-Table -AutoSize

# Stop Transcript & Finish
Stop-Transcript
Write-Output "=== Transcript: $TranscriptPath ==="
Write-Output "=== Prefetch Copies: $PrefetchFolder ==="
Write-Output "=== RAM Dump: $PSScriptRoot ==="

# Might be a good idea to hash any outputs just in case this would include the imaging of the hard drive (different script) and the RAM dump (this script)