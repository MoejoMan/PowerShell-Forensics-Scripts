# Forensic Data Collection Script
param(
    [switch]$SkipRamDump,
    [switch]$SkipHashes,
    [string]$VmLabel    = "Default",
    [switch]$BatchMode          # NEW: run interactive multi-VM loop
)

Set-ExecutionPolicy Bypass -Scope Process -Force

# ============================================================================
# INITIALIZATION
# ============================================================================
. "$PSScriptRoot\functions.ps1"
. "$PSScriptRoot\advanced_functions.ps1"
. "$PSScriptRoot\new_functions.ps1"
. "$PSScriptRoot\email_pagefile_functions.ps1"

# Load PowerForensics module from bin\ if available (for $MFT, Prefetch, USN, etc.)
$pfModulePath = Join-Path $PSScriptRoot "bin\PowerForensicsv2\PowerForensicsv2.psd1"
if (Test-Path $pfModulePath) {
    try {
        # Remove MOTW zone tags so .NET will load the DLL (downloaded files are blocked by default)
        Get-ChildItem (Split-Path $pfModulePath) -Recurse | Unblock-File -ErrorAction SilentlyContinue
        Import-Module $pfModulePath -Force -ErrorAction Stop
        Write-Host "[PowerForensics] Module loaded from bin\PowerForensicsv2\"
    } catch {
        Write-Host "[PowerForensics] WARNING: Failed to load module - $_"
    }
} else {
    Write-Host "[PowerForensics] Module not found at bin\PowerForensicsv2\ (optional)"
}

# ── Batch mode: hand off to the multi-VM orchestrator and exit ───────────────
if ($BatchMode) {
    $baseOut = $PSScriptRoot
    Invoke-MultiVMCollection -ScriptRoot $PSScriptRoot -BaseOutputPath $baseOut
    exit
}

# Set up output paths (per-VM label to keep evidence separated)
$scriptRoot      = $PSScriptRoot
$safeLabel       = ($VmLabel -replace '[^a-zA-Z0-9_-]', '_')
$evidencePath    = "$scriptRoot\Evidence\$safeLabel"
$transcriptPath  = "$scriptRoot\Transcript\$safeLabel"
$htmlReportPath  = "$scriptRoot\HTMLReport\$safeLabel"

# Create output directories
New-Item -ItemType Directory -Path $evidencePath, $transcriptPath, $htmlReportPath -Force | Out-Null

# Set up logging (ACPO Principle 3 - Audit Trail)
$logFile = "$transcriptPath\collection_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $logFile -Append

Write-Host "=========================================="
Write-Host "FORENSIC DATA COLLECTION"
Write-Host "=========================================="
Write-Host "Start Time : $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
Write-Host "VM Label   : $safeLabel"
Write-Host ""

# Collection result tracker
$script:collectionResults = [System.Collections.ArrayList]::new()
function Add-CollectionResult {
    param([string]$Name, [object]$Result)
    # Note: PowerShell unwraps empty arrays to $null, so $null means "none found" not "error".
    # Actual errors are logged by each function via Write-Host. This tracks data yield only.
    $status = if ($null -eq $Result) { 'None' }
              elseif ($Result -is [string]) { 'OK' }
              elseif ($Result -is [array] -and $Result.Count -eq 0) { 'None' }
              else { 'OK' }
    $count = if ($null -eq $Result) { 0 }
             elseif ($Result -is [array]) { $Result.Count }
             elseif ($Result -is [string]) { 1 }
             elseif ($Result -and $Result.PSObject.Properties) { 1 }
             else { 0 }
    $null = $script:collectionResults.Add([pscustomobject]@{
        Artifact = $Name
        Status   = $status
        Count    = $count
    })
}

try {
    # ========================================================================
    # PRIORITY 1: VOLATILE DATA (RAM)
    # ========================================================================
    $skipRam = $SkipRamDump -or ($env:SKIP_RAM_DUMP -eq "1")
    Write-Output "PRIORITY 1: Capturing live RAM (volatile data)"
    Write-Output ""

    if ($skipRam) {
        Write-Output "RAM dump skipped by operator"
        $ramResult = [pscustomobject]@{ Success = $false; Path = $null; Error = "Skipped" }
    } else {
        $ramResult = Export-MemoryDump -OutputPath $evidencePath
    }
    Write-Output ""

    if (-not $ramResult.Success) {
        $ramError = $ramResult.Error
        if (-not $ramError) { $ramError = "Unknown error" }
        Write-Output "WARNING: RAM dump failed - continuing with other collections ($ramError)"
    }

    # ========================================================================
    # PRIORITY 2: NON-VOLATILE DATA
    # ========================================================================
    Write-Output "PRIORITY 2: Collecting system data"
    Write-Output ""

    $processes      = Get-ProcessList          -OutputPath $evidencePath
    Write-Output ""
    $systemInfo      = Get-SystemInfo            -OutputPath $evidencePath
    Write-Output ""
    $users          = Get-UserList             -OutputPath $evidencePath
    Write-Output ""
    $tcpConnections = Get-NetworkConnections   -OutputPath $evidencePath
    Write-Output ""
    $neighbors      = Get-NetworkNeighbors     -OutputPath $evidencePath
    Write-Output ""
    $prefetch       = Get-PrefetchFiles        -OutputPath $evidencePath
    Write-Output ""
    $installedPrograms = Get-InstalledPrograms -OutputPath $evidencePath
    Write-Output ""
    $services       = Get-ServicesList         -OutputPath $evidencePath
    Write-Output ""
    $scheduledTasks = Get-ScheduledTasksList   -OutputPath $evidencePath
    Write-Output ""
    $networkConfig  = Get-NetworkConfig        -OutputPath $evidencePath
    Write-Output ""
    $autoruns       = Get-Autoruns             -OutputPath $evidencePath
    Write-Output ""
    $browserArtifacts = Get-BrowserArtifactsAndDownloads -OutputPath $evidencePath
    Write-Output ""
    $wmiPersistence = Get-WmiPersistence       -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 2.5: FULL EVENT LOGS  (replaces old 3-day triage)
    # ========================================================================
    Write-Output "PRIORITY 2.5: Exporting full event logs (all history + key event triage)"
    Write-Output ""

    $eventLogs = Get-FullEventLogs -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 3: ANTI-FORENSICS & CONCEALMENT
    # ========================================================================
    Write-Output "PRIORITY 3: Scanning for hidden mechanisms & concealment"
    Write-Output ""

    $altDataStreams      = Get-AlternateDataStreams        -OutputPath $evidencePath
    Write-Output ""
    $hiddenFiles         = Get-HiddenFiles                 -OutputPath $evidencePath
    Write-Output ""
    $encryptedVolumes    = Get-EncryptedVolumeDetection    -OutputPath $evidencePath
    Write-Output ""
    $shadowCopies        = Get-ShadowCopies                -OutputPath $evidencePath
    Write-Output ""
    $timestompedFiles    = Get-TimestompDetection          -OutputPath $evidencePath
    Write-Output ""
    $defenderExclusions  = Get-DefenderExclusions          -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 4: FILE PROVENANCE & USER ACTIVITY
    # ========================================================================
    Write-Output "PRIORITY 4: Collecting file provenance and user activity traces"
    Write-Output ""

    $zoneIdentifiers = Get-ZoneIdentifierInfo      -OutputPath $evidencePath
    Write-Output ""
    $recentActivity  = Get-RecentFileActivity       -OutputPath $evidencePath
    Write-Output ""
    $usbDevices      = Get-USBDeviceHistory         -OutputPath $evidencePath
    Write-Output ""
    $recycleBin      = Get-RecycleBinContents       -OutputPath $evidencePath
    Write-Output ""
    $userAssist      = Get-UserAssistHistory        -OutputPath $evidencePath
    Write-Output ""
    $hostsFileEntries = Get-HostsFileCheck          -OutputPath $evidencePath
    Write-Output ""
    $firewallRules   = Get-FirewallRules            -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 4.5: DEEP-DIVE ARTIFACTS
    # ========================================================================
    Write-Output "PRIORITY 4.5: Deep-dive artifact collection"
    Write-Output ""

    $wifiProfiles        = Get-WiFiProfiles          -OutputPath $evidencePath
    Write-Output ""
    $wallpaperInfo       = Get-WallpaperInfo         -OutputPath $evidencePath
    Write-Output ""
    $browserBookmarks    = Get-BrowserBookmarks      -OutputPath $evidencePath
    Write-Output ""
    $browserSearchHistory = Get-BrowserSearchHistory -OutputPath $evidencePath
    Write-Output ""
    $windowsTimeline     = Get-WindowsTimeline       -OutputPath $evidencePath
    Write-Output ""
    $gameArtifacts       = Get-GameArtifacts         -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 5: VOLATILE / TIME-SENSITIVE
    # ========================================================================
    Write-Output "PRIORITY 5: Capturing volatile evidence (DNS, clipboard, sessions)"
    Write-Output ""

    $dnsCache     = Get-DNSCache                -OutputPath $evidencePath
    Write-Output ""
    $clipboardText = Get-ClipboardContents      -OutputPath $evidencePath
    Write-Output ""
    $mappedDrives  = Get-MappedDrivesAndShares  -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 6: COMMAND HISTORY & REMOTE ACCESS
    # ========================================================================
    Write-Output "PRIORITY 6: Collecting command history and remote access artifacts"
    Write-Output ""

    $psHistory   = Get-PowerShellHistory        -OutputPath $evidencePath
    Write-Output ""
    $rdpSessions = Get-RDPAndRemoteSessions     -OutputPath $evidencePath
    Write-Output ""

    # ========================================================================
    # PRIORITY 7: REGISTRY HIVES, EXECUTION EVIDENCE & FILE METADATA
    # (variables used below in New-HTMLReport call)
    # ========================================================================
    Write-Output "PRIORITY 7: Registry hives, execution artefacts, LNK files"
    Write-Output ""

    $registryHives  = Get-RegistryHives          -OutputPath $evidencePath
    Write-Output ""
    $srumDb         = Get-SRUMDatabase           -OutputPath $evidencePath
    Write-Output ""
    $amcache        = Get-AmcacheAndShimcache    -OutputPath $evidencePath
    Write-Output ""
    $lnkFiles       = Get-LnkAndJumpLists       -OutputPath $evidencePath
    Write-Output ""
    $thumbCache     = Get-ThumbnailCache        -OutputPath $evidencePath
    Write-Output ""
    $mftUsn         = Get-MFTAndUsnJournal      -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Output ""

    # ========================================================================
    # PRIORITY 8: EMAILS AND MEMORY FILES
    # (variables used below in New-HTMLReport call)
    # ========================================================================
    Write-Output "PRIORITY 8: Email artefacts and memory files (pagefile/hiberfil)"
    Write-Output ""

    $emailArtefacts  = Get-EmailArtefacts         -OutputPath $evidencePath
    Write-Output ""
    $memoryFiles     = Get-PagefileAndHiberfil    -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Output ""

    # Track collection results for final summary
    Add-CollectionResult 'RAM Dump'           $(if ($ramResult.Success) { $ramResult } else { $null })
    Add-CollectionResult 'System Info'        $systemInfo
    Add-CollectionResult 'Processes'          $processes
    Add-CollectionResult 'Users'              $users
    Add-CollectionResult 'TCP Connections'    $tcpConnections
    Add-CollectionResult 'Neighbors'          $neighbors
    Add-CollectionResult 'Prefetch'           $prefetch
    Add-CollectionResult 'Installed Programs' $installedPrograms
    Add-CollectionResult 'Services'           $services
    Add-CollectionResult 'Scheduled Tasks'    $scheduledTasks
    Add-CollectionResult 'Network Config'     $networkConfig
    Add-CollectionResult 'Autoruns'           $autoruns
    Add-CollectionResult 'Browser Artifacts'  $(if ($browserArtifacts) { @($browserArtifacts.BrowserCopies) + @($browserArtifacts.Downloads) | Where-Object { $_ } } else { $null })
    Add-CollectionResult 'WMI Persistence'    $wmiPersistence
    Add-CollectionResult 'Event Logs'         $(if ($eventLogs) { @($eventLogs.Security) + @($eventLogs.System) + @($eventLogs.Application) | Where-Object { $_ } } else { $null })
    Add-CollectionResult 'ADS'                $altDataStreams
    Add-CollectionResult 'Hidden Files'       $hiddenFiles
    Add-CollectionResult 'Encrypted Volumes'  $encryptedVolumes
    Add-CollectionResult 'Shadow Copies'      $shadowCopies
    Add-CollectionResult 'Timestomped Files'  $timestompedFiles
    Add-CollectionResult 'Defender Exclusions' $defenderExclusions
    Add-CollectionResult 'Zone Identifiers'   $zoneIdentifiers
    Add-CollectionResult 'Recent Activity'    $recentActivity
    Add-CollectionResult 'USB Devices'        $usbDevices
    Add-CollectionResult 'Recycle Bin'        $recycleBin
    Add-CollectionResult 'UserAssist'         $userAssist
    Add-CollectionResult 'Hosts File'         $hostsFileEntries
    Add-CollectionResult 'Firewall Rules'     $firewallRules
    Add-CollectionResult 'WiFi Profiles'      $wifiProfiles
    Add-CollectionResult 'Wallpaper'          $wallpaperInfo
    Add-CollectionResult 'Bookmarks'          $browserBookmarks
    Add-CollectionResult 'Search History'     $browserSearchHistory
    Add-CollectionResult 'Windows Timeline'   $windowsTimeline
    Add-CollectionResult 'Game Artifacts'     $gameArtifacts
    Add-CollectionResult 'DNS Cache'          $dnsCache
    Add-CollectionResult 'Clipboard'          $clipboardText
    Add-CollectionResult 'Mapped Drives'      $mappedDrives
    Add-CollectionResult 'PS History'         $psHistory
    Add-CollectionResult 'RDP Sessions'       $rdpSessions
    Add-CollectionResult 'Registry Hives'     $(if ($registryHives -and (Get-ChildItem $registryHives -File -ErrorAction SilentlyContinue)) { $registryHives } else { $null })
    Add-CollectionResult 'SRUM Database'      $(if ($srumDb -and (Test-Path $srumDb)) { $srumDb } else { $null })
    Add-CollectionResult 'Amcache'            $(if ($amcache -and (Test-Path $amcache)) { $amcache } else { $null })
    Add-CollectionResult 'LNK Files'          $lnkFiles
    Add-CollectionResult 'Thumbnail Cache'    $(if ($thumbCache -and (Get-ChildItem $thumbCache -File -ErrorAction SilentlyContinue)) { $thumbCache } else { $null })
    Add-CollectionResult 'MFT/USN Journal'    $(if ($mftUsn -and (Get-ChildItem $mftUsn -File -ErrorAction SilentlyContinue)) { $mftUsn } else { $null })
    Add-CollectionResult 'Email Artefacts'    $emailArtefacts
    Add-CollectionResult 'Memory Files'       $memoryFiles

    # ========================================================================
    # FILE HASHING (INTEGRITY)
    # ========================================================================
    $hashes = $null
    if (-not ($SkipHashes -or ($env:SKIP_HASHES -eq "1"))) {
        $filesToHash = Get-ChildItem -Path $evidencePath -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne '.raw' }   # skip the RAM dump itself (too large)
        if ($filesToHash) {
            Write-Output "=== Calculating File Hashes (SHA256) ==="
            $hashes = Get-FileHashes -Files $filesToHash
            if ($hashes) {
                $hashes | Export-Csv "$evidencePath\hashes.csv" -NoTypeInformation -Encoding UTF8
                Write-Output "Hashes saved to: $evidencePath\hashes.csv"
            }
        }
        Write-Output ""
    } else {
        Write-Output "Skipping file hashes"
        Write-Output ""
    }

    # ========================================================================
    # MEMORY ANALYSIS: Volatility 3 + Strings Extraction (requires RAM dump)
    # ========================================================================
    $memoryStrings = $null
    if ($ramResult.Success -and $ramResult.Path) {
        $memoryStrings = Get-MemoryStrings -OutputPath $evidencePath -RamDumpPath $ramResult.Path -ScriptRoot $scriptRoot
        Write-Output ""
    } else {
        Write-Output "Skipping memory analysis (no RAM dump available)"
        Write-Output ""
    }

    # ========================================================================
    # HTML REPORT
    # ========================================================================
    New-HTMLReport -OutputPath $htmlReportPath `
                   -SystemInfo $systemInfo `
                   -Processes $processes `
                   -Users $users `
                   -TCPConnections $tcpConnections `
                   -Neighbors $neighbors `
                   -PrefetchFiles $prefetch `
                   -InstalledPrograms $installedPrograms `
                   -Services $services `
                   -ScheduledTasks $scheduledTasks `
                   -NetworkConfig $networkConfig `
                   -Autoruns $autoruns `
                   -BrowserArtifacts $browserArtifacts `
                   -EventLogSecurity $eventLogs.Security `
                   -EventLogSystem $eventLogs.System `
                   -EventLogApplication $eventLogs.Application `
                   -WmiPersistence $wmiPersistence `
                   -RamResult $ramResult `
                   -FileHashes $hashes `
                   -AlternateDataStreams $altDataStreams `
                   -HiddenFiles $hiddenFiles `
                   -EncryptedVolumes $encryptedVolumes `
                   -ZoneIdentifiers $zoneIdentifiers `
                   -RecentActivity $recentActivity `
                   -USBDevices $usbDevices `
                   -RecycleBin $recycleBin `
                   -DNSCache $dnsCache `
                   -ClipboardText $clipboardText `
                   -MappedDrives $mappedDrives `
                   -PSHistory $psHistory `
                   -RDPSessions $rdpSessions `
                   -MemoryStrings $memoryStrings `
                   -ShadowCopies $shadowCopies `
                   -TimestompedFiles $timestompedFiles `
                   -UserAssist $userAssist `
                   -HostsFileEntries $hostsFileEntries `
                   -FirewallRules $firewallRules `
                   -DefenderExclusions $defenderExclusions `
                   -WiFiProfiles $wifiProfiles `
                   -WallpaperInfo $wallpaperInfo `
                   -BrowserBookmarks $browserBookmarks `
                   -BrowserSearchHistory $browserSearchHistory `
                   -WindowsTimeline $windowsTimeline `
                   -GameArtifacts $gameArtifacts `
                   -RegistryHives $registryHives `
                   -SRUMDatabase $srumDb `
                   -Amcache $amcache `
                   -LnkFiles $lnkFiles `
                   -ThumbnailCache $thumbCache `
                   -MFTUsn $mftUsn `
                   -EmailArtefacts $emailArtefacts `
                   -MemoryFiles $memoryFiles
    Write-Output ""

} catch {
    Write-Output "FATAL ERROR: $_"
    Write-Output $_.ScriptStackTrace
} finally {
    Write-Output "=========================================="
    Write-Output "Collection Complete"
    Write-Output "End Time: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
    Write-Output ""
    Write-Output "Output locations:"
    Write-Output "  Evidence data : $evidencePath"
    Write-Output "  HTML report   : $htmlReportPath\forensic_report.html"
    Write-Output "  Transcript log: $logFile"
    Write-Output "=========================================="

    # Print collection summary
    if ($script:collectionResults.Count -gt 0) {
        Write-Output ""
        Write-Output "=== COLLECTION SUMMARY ==="
        $okCount    = @($script:collectionResults | Where-Object { $_.Status -eq 'OK' }).Count
        $noneCount  = @($script:collectionResults | Where-Object { $_.Status -eq 'None' }).Count
        Write-Output "  Collected: $okCount | No data: $noneCount"
        if ($noneCount -gt 0) {
            Write-Output ""
            Write-Output "  No data found for:"
            $script:collectionResults | Where-Object { $_.Status -eq 'None' } | ForEach-Object {
                Write-Output "    - $($_.Artifact)"
            }
        }
        Write-Output "=========================================="
    }

    Stop-Transcript
}

# ============================================================================
# SLEEPING VM IMAGE ACQUISITION (runs after live triage + transcript close)
# ============================================================================
# This runs outside the try/finally so the live evidence is already safe.
# FTK Imager creates an E01 forensic image of the sleeping VM's VMDK and
# copies any .vmem memory snapshot for Volatility analysis.
Write-Host ""
Write-Host "=========================================="
Write-Host "  SLEEPING VM ACQUISITION"
Write-Host "=========================================="
Write-Host ""
Write-Host "If there is a sleeping/suspended VM at the scene, you should image"
Write-Host "its VMDK disk file now. This creates an E01 forensic image + hashes."
Write-Host ""

$doSleepingVM = Read-Host "Image a sleeping VM? (Y/N)"
if ($doSleepingVM -eq 'Y' -or $doSleepingVM -eq 'y') {

    $vmdkInput = Read-Host "Enter full path to VMDK/VHD file (or press Enter to auto-search C:\)"
    $sleepLabel = Read-Host "Enter a label for this VM (e.g. VM2_Sleeping)"
    if (-not $sleepLabel) { $sleepLabel = "VM2_Sleeping" }

    $sleepOutputPath = "$scriptRoot\Evidence\$sleepLabel"
    New-Item -ItemType Directory -Path $sleepOutputPath -Force | Out-Null

    # Start transcript BEFORE any work so prompts + output are captured
    $sleepTranscript = "$scriptRoot\Transcript\${sleepLabel}\transcript_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    New-Item -ItemType Directory -Path (Split-Path $sleepTranscript) -Force | Out-Null
    Start-Transcript -Path $sleepTranscript -Force

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting sleeping VM acquisition: $sleepLabel"

    Get-SleepingVMArtefacts -OutputPath $sleepOutputPath `
                            -ScriptRoot $scriptRoot `
                            -VmLabel $sleepLabel `
                            -VmdkPath $vmdkInput

    # Generate hashes of the acquired image files
    Write-Host ""
    Write-Host "=== Hashing acquired image files ==="
    $imageFiles = Get-ChildItem "$sleepOutputPath" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(E01|001|raw|vmem|vmsn|vmss)$' }
    $imageHashResults = @()
    foreach ($img in $imageFiles) {
        Write-Host "  Hashing $($img.Name)..."
        $md5  = (Get-FileHash $img.FullName -Algorithm MD5).Hash
        $sha1 = (Get-FileHash $img.FullName -Algorithm SHA1).Hash
        $sha256 = (Get-FileHash $img.FullName -Algorithm SHA256).Hash
        Write-Host "    MD5   : $md5"
        Write-Host "    SHA1  : $sha1"
        Write-Host "    SHA256: $sha256"
        $imageHashResults += [pscustomobject]@{
            File   = $img.Name
            MD5    = $md5
            SHA1   = $sha1
            SHA256 = $sha256
            SizeMB = [math]::Round($img.Length / 1MB, 1)
        }
    }
    if ($imageHashResults) {
        $imageHashResults | Export-Csv "$sleepOutputPath\image_hashes.csv" -NoTypeInformation -Encoding UTF8
    }
    Write-Host "Image hashes saved to: $sleepOutputPath\image_hashes.csv"

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Sleeping VM acquisition complete."
    Write-Host "Evidence: $sleepOutputPath"
    Write-Host "=========================================="

    Stop-Transcript
} else {
    Write-Host "Skipping sleeping VM acquisition."
}
