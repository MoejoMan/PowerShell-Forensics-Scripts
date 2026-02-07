# Start Transcript
$TranscriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $TranscriptPath

# Dump RAM with DumpIt
Write-Output "=== Dumping RAM ==="
& "$PSScriptRoot\DumpIt.exe" /quiet /accepteula

# Stop Transcript & Finish
Stop-Transcript
Write-Output "=== Transcript: $TranscriptPath ==="
Write-Output "=== RAM Dump: $PSScriptRoot ==="

# Might be a good idea to hash any outputs just in case this would include the imaging of the hard drive (different script) and the RAM dump (this script)