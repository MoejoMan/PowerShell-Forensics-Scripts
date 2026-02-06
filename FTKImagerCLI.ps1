# Bypass execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Paths and Outputs 
$VMDK_Path = "C:\PathToVMDK\SuperSuspectVMDKFile.vmdk"
$OutputFolder = "$PSScriptRoot\ForensicImage"
$FTK_Imager_Path = "$PSScriptRoot\ftkimager.exe"

# Start transcript
$TranscriptPath = "$PSScriptRoot\Transcript_$(Get-Date -Format 'ddMMYYYY-HHmmss').log"
Start-Transcript -Path $TranscriptPath

# Create output folder
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

# Step 1: Create forensic image of the VMDK using FTK Imager CLI
Write-Output "=== Creating Forensic Image of VMDK ==="
& $FTK_Imager_Path $VMDK_Path "$OutputFolder\ForensicImage" --e01 --frag 2GB --compress 0 --description "ForensicImage_VMDK" --case-number ARU0001 --evidence-number StudentSID0001 --examiner "AwesomePerson"

# Step 2: Generate hashes
Write-Output "=== Generating Hashes ==="
Get-FileHash -Path "$OutputFolder\ForensicImage.E01" -Algorithm MD5 | Format-List
Get-FileHash -Path $VMDK_Path -Algorithm MD5 | Format-List
Get-FileHash -Path "$OutputFolder\ForensicImage.E01" -Algorithm SHA1 | Format-List
Get-FileHash -Path $VMDK_Path -Algorithm SHA1 | Format-List

# Step 3: Verify image integrity
Write-Output "=== Verifying Image ==="
& $FTK_Imager_Path --verify "$OutputFolder\ForensicImage.E01"

# Stop Script and Report to Screen
Stop-Transcript
Write-Output "=== Forensic Image: $OutputFolder ==="
Write-Output "=== Transcript: $TranscriptPath ==="