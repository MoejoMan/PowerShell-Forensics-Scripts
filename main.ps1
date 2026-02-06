# Bypass execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Import the functions
. "$PSScriptRoot\functions.ps1"

# Set up logging
$transcriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $transcriptPath -Append

Write-Output "=== Forensic Data Collection ==="
Write-Output "Timestamp: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
Write-Output ""

# Call the functions
Get-ProcessList
Write-Output ""

Get-UserList
Write-Output ""

Get-PrefetchFiles
Write-Output ""

Write-Output "=== Collection Complete ==="
Write-Output "Log saved to: $transcriptPath"

# Stop logging
Stop-Transcript