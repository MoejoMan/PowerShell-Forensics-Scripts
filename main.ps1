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
Write-Host "ACPO Good Practice Guide Compliance:"
Write-Host "  Principle 1: No action taken should change data on a digital device"
Write-Host "               which may subsequently be relied upon in court."
Write-Host "  Principle 2: Where a person finds it necessary to access original data,"
Write-Host "               that person must be competent to do so and able to give"
Write-Host "               evidence explaining the relevance and implications of their actions."
Write-Host "  Principle 3: An audit trail or other record of all processes applied to"
Write-Host "               digital evidence should be created and preserved. An independent"
Write-Host "               third party should be able to examine those processes and achieve"
Write-Host "               the same result."
Write-Host "  Principle 4: The person in charge of the investigation has overall responsibility"
Write-Host "               for ensuring that the law and these principles are adhered to."
Write-Host ""
Write-Host "ISO 27037: Digital evidence identification, collection, acquisition, and preservation."
Write-Host "All evidence files are SHA256 hashed. A full transcript log is maintained."
Write-Host "=========================================="
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
    Write-Host "PRIORITY 1: Capturing live RAM (volatile data)"
    Write-Host ""

    if ($skipRam) {
        Write-Host "RAM dump skipped by operator"
        $ramResult = [pscustomobject]@{ Success = $false; Path = $null; Error = "Skipped" }
    } else {
        $ramResult = Export-MemoryDump -OutputPath $evidencePath
    }
    Write-Host ""

    if (-not $ramResult.Success) {
        $ramError = $ramResult.Error
        if (-not $ramError) { $ramError = "Unknown error" }
        Write-Host "WARNING: RAM dump failed - continuing with other collections ($ramError)"
    }

    # ========================================================================
    # PRIORITY 2: NON-VOLATILE DATA
    # ========================================================================
    Write-Host "PRIORITY 2: Collecting system data"
    Write-Host ""

    $processes      = Get-ProcessList          -OutputPath $evidencePath
    Write-Host ""
    $systemInfo      = Get-SystemInfo            -OutputPath $evidencePath
    Write-Host ""
    $users          = Get-UserList             -OutputPath $evidencePath
    Write-Host ""
    $tcpConnections = Get-NetworkConnections   -OutputPath $evidencePath
    Write-Host ""
    $neighbors      = Get-NetworkNeighbors     -OutputPath $evidencePath
    Write-Host ""
    $prefetch       = Get-PrefetchFiles        -OutputPath $evidencePath
    Write-Host ""
    $installedPrograms = Get-InstalledPrograms -OutputPath $evidencePath
    Write-Host ""
    $services       = Get-ServicesList         -OutputPath $evidencePath
    Write-Host ""
    $scheduledTasks = Get-ScheduledTasksList   -OutputPath $evidencePath
    Write-Host ""
    $networkConfig  = Get-NetworkConfig        -OutputPath $evidencePath
    Write-Host ""
    $autoruns       = Get-Autoruns             -OutputPath $evidencePath
    Write-Host ""
    $browserArtifacts = Get-BrowserArtifactsAndDownloads -OutputPath $evidencePath
    Write-Host ""
    $wmiPersistence = Get-WmiPersistence       -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 2.5: FULL EVENT LOGS  (replaces old 3-day triage)
    # ========================================================================
    Write-Host "PRIORITY 2.5: Exporting full event logs (all history + key event triage)"
    Write-Host ""

    $eventLogs = Get-FullEventLogs -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 3: ANTI-FORENSICS & CONCEALMENT
    # ========================================================================
    Write-Host "PRIORITY 3: Scanning for hidden mechanisms & concealment"
    Write-Host ""

    $altDataStreams      = Get-AlternateDataStreams        -OutputPath $evidencePath
    Write-Host ""
    $hiddenFiles         = Get-HiddenFiles                 -OutputPath $evidencePath
    Write-Host ""
    $encryptedVolumes    = Get-EncryptedVolumeDetection    -OutputPath $evidencePath
    Write-Host ""
    $shadowCopies        = Get-ShadowCopies                -OutputPath $evidencePath
    Write-Host ""
    $timestompedFiles    = Get-TimestompDetection          -OutputPath $evidencePath
    Write-Host ""
    $defenderExclusions  = Get-DefenderExclusions          -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 4: FILE PROVENANCE & USER ACTIVITY
    # ========================================================================
    Write-Host "PRIORITY 4: Collecting file provenance and user activity traces"
    Write-Host ""

    $zoneIdentifiers = Get-ZoneIdentifierInfo      -OutputPath $evidencePath
    Write-Host ""
    $recentActivity  = Get-RecentFileActivity       -OutputPath $evidencePath
    Write-Host ""
    $usbDevices      = Get-USBDeviceHistory         -OutputPath $evidencePath
    Write-Host ""
    $recycleBin      = Get-RecycleBinContents       -OutputPath $evidencePath
    Write-Host ""
    $userAssist      = Get-UserAssistHistory        -OutputPath $evidencePath
    Write-Host ""
    $hostsFileEntries = Get-HostsFileCheck          -OutputPath $evidencePath
    Write-Host ""
    $firewallRules   = Get-FirewallRules            -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 4.5: DEEP-DIVE ARTIFACTS
    # ========================================================================
    Write-Host "PRIORITY 4.5: Deep-dive artifact collection"
    Write-Host ""

    $wifiProfiles        = Get-WiFiProfiles          -OutputPath $evidencePath
    Write-Host ""
    $wallpaperInfo       = Get-WallpaperInfo         -OutputPath $evidencePath
    Write-Host ""
    $browserBookmarks    = Get-BrowserBookmarks      -OutputPath $evidencePath
    Write-Host ""
    $browserSearchHistory = Get-BrowserSearchHistory -OutputPath $evidencePath
    Write-Host ""
    $windowsTimeline     = Get-WindowsTimeline       -OutputPath $evidencePath
    Write-Host ""
    $gameArtifacts       = Get-GameArtifacts         -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 5: VOLATILE / TIME-SENSITIVE
    # ========================================================================
    Write-Host "PRIORITY 5: Capturing volatile evidence (DNS, clipboard, sessions)"
    Write-Host ""

    $dnsCache     = Get-DNSCache                -OutputPath $evidencePath
    Write-Host ""
    $clipboardText = Get-ClipboardContents      -OutputPath $evidencePath
    Write-Host ""
    $mappedDrives  = Get-MappedDrivesAndShares  -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 6: COMMAND HISTORY & REMOTE ACCESS
    # ========================================================================
    Write-Host "PRIORITY 6: Collecting command history and remote access artifacts"
    Write-Host ""

    $psHistory   = Get-PowerShellHistory        -OutputPath $evidencePath
    Write-Host ""
    $rdpSessions = Get-RDPAndRemoteSessions     -OutputPath $evidencePath
    Write-Host ""

    # ========================================================================
    # PRIORITY 7: REGISTRY HIVES, EXECUTION EVIDENCE & FILE METADATA
    # (variables used below in New-HTMLReport call)
    # ========================================================================
    Write-Host "PRIORITY 7: Registry hives, execution artefacts, LNK files"
    Write-Host ""

    $registryHives  = Get-RegistryHives          -OutputPath $evidencePath
    Write-Host ""
    $srumDb         = Get-SRUMDatabase           -OutputPath $evidencePath
    Write-Host ""
    $amcache        = Get-AmcacheAndShimcache    -OutputPath $evidencePath
    Write-Host ""
    $lnkFiles       = Get-LnkAndJumpLists       -OutputPath $evidencePath
    Write-Host ""
    $thumbCache     = Get-ThumbnailCache        -OutputPath $evidencePath
    Write-Host ""
    $mftUsn         = Get-MFTAndUsnJournal      -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Host ""

    # ========================================================================
    # PRIORITY 8: EMAILS AND MEMORY FILES
    # (variables used below in New-HTMLReport call)
    # ========================================================================
    Write-Host "PRIORITY 8: Email artefacts and memory files (pagefile/hiberfil)"
    Write-Host ""

    $emailArtefacts  = Get-EmailArtefacts         -OutputPath $evidencePath
    Write-Host ""
    $emlMsgFiles     = Get-EmlMsgFiles            -OutputPath $evidencePath
    Write-Host ""
    $memoryFiles     = Get-PagefileAndHiberfil    -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Host ""

    # ========================================================================
    # PRIORITY 9: TARGETED INVESTIGATION SCANS (Criterion B - extortion evidence)
    # ========================================================================
    Write-Host "PRIORITY 9: Targeted investigation scans (extortion indicators)"
    Write-Host ""

    $extortionIndicators = Search-ExtortionIndicators -OutputPath $evidencePath
    Write-Host ""

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
    Add-CollectionResult 'EML/MSG Files'      $emlMsgFiles
    Add-CollectionResult 'Memory Files'       $memoryFiles
    Add-CollectionResult 'Extortion Indicators' $extortionIndicators

    # ========================================================================
    # FILE HASHING (INTEGRITY)
    # ========================================================================
    $hashes = $null
    if (-not ($SkipHashes -or ($env:SKIP_HASHES -eq "1"))) {
        $filesToHash = Get-ChildItem -Path $evidencePath -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne '.raw' }   # skip the RAM dump itself (too large)
        if ($filesToHash) {
            Write-Host "=== Calculating File Hashes (SHA256) ==="
            $hashes = Get-FileHashes -Files $filesToHash
            if ($hashes) {
                $hashes | Export-Csv "$evidencePath\hashes.csv" -NoTypeInformation -Encoding UTF8
                Write-Host "Hashes saved to: $evidencePath\hashes.csv"
            }
        }
        Write-Host ""
    } else {
        Write-Host "Skipping file hashes"
        Write-Host ""
    }

    # ========================================================================
    # MEMORY ANALYSIS: Volatility 3 + Strings Extraction (requires RAM dump)
    # ========================================================================
    $memoryStrings = $null
    if ($ramResult.Success -and $ramResult.Path) {
        $memoryStrings = Get-MemoryStrings -OutputPath $evidencePath -RamDumpPath $ramResult.Path -ScriptRoot $scriptRoot
        Write-Host ""
    } else {
        Write-Host "Skipping memory analysis (no RAM dump available)"
        Write-Host ""
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
                   -EmlMsgFiles $emlMsgFiles `
                   -MemoryFiles $memoryFiles `
                   -ExtortionIndicators $extortionIndicators `
                   -VmLabel $safeLabel
    Write-Host ""

} catch {
    Write-Host "FATAL ERROR: $_"
    Write-Host $_.ScriptStackTrace
} finally {
    Write-Host "=========================================="
    Write-Host "Collection Complete"
    Write-Host "End Time: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
    Write-Host ""
    Write-Host "Output locations:"
    Write-Host "  Evidence data : $evidencePath"
    Write-Host "  HTML report   : $htmlReportPath\forensic_report.html"
    Write-Host "  Transcript log: $logFile"
    Write-Host "=========================================="

    # Print collection summary
    if ($script:collectionResults.Count -gt 0) {
        Write-Host ""
        Write-Host "=== COLLECTION SUMMARY ==="
        $okCount    = @($script:collectionResults | Where-Object { $_.Status -eq 'OK' }).Count
        $noneCount  = @($script:collectionResults | Where-Object { $_.Status -eq 'None' }).Count
        Write-Host "  Collected: $okCount | No data: $noneCount"
        if ($noneCount -gt 0) {
            Write-Host ""
            Write-Host "  No data found for:"
            $script:collectionResults | Where-Object { $_.Status -eq 'None' } | ForEach-Object {
                Write-Host "    - $($_.Artifact)"
            }
        }
        Write-Host "=========================================="
    }

    Stop-Transcript
}

# ============================================================================
# VM IMAGE ACQUISITION (runs after live triage + transcript close)
# ============================================================================
# This runs outside the try/finally so the live evidence is already safe.
# The brief specifies TWO VMs: one sleeping (has .vmem memory) and one
# switched off (VMDK only, no live memory). This loop lets the investigator
# image both sequentially from the host machine.
#
# For the SLEEPING VM: FTK Imager creates an E01 of the VMDK, copies .vmem,
#   then runs Volatility + strings on the .vmem (Criterion D: memory links).
# For the OFF VM: FTK Imager creates an E01 of the VMDK for offline analysis.

$vmNumber = 0
do {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  VM IMAGE ACQUISITION"
    Write-Host "=========================================="
    Write-Host ""
    if ($vmNumber -eq 0) {
        Write-Host "The brief specifies TWO VMs on the host machine:"
        Write-Host "  1. A sleeping/suspended VM (has .vmem memory snapshot)"
        Write-Host "  2. A switched-off VM (VMDK only, no live memory)"
        Write-Host ""
        Write-Host "You should image BOTH VMs from the host before leaving the scene."
        Write-Host "The host computer itself contains no evidential data."
    } else {
        Write-Host "VM #$vmNumber imaging complete. You can image another VM now."
    }
    Write-Host ""

    $doVM = Read-Host "Image a VM from the host? (Y/N)"
    if ($doVM -ne 'Y' -and $doVM -ne 'y') {
        if ($vmNumber -eq 0) {
            Write-Host "Skipping all VM imaging."
        } else {
            Write-Host "No more VMs to image."
        }
        break
    }

    $vmNumber++

    # Ask what type of VM this is
    Write-Host ""
    Write-Host "What type of VM is this?"
    Write-Host "  1. Sleeping/Suspended VM (has .vmem memory - will run Volatility analysis)"
    Write-Host "  2. Switched-off VM (VMDK only - disk image for offline analysis)"
    $vmType = Read-Host "Enter 1 or 2"
    $isSleeping = ($vmType -eq '1')

    $vmdkInput = Read-Host "Enter full path to VMDK/VHD file (or press Enter to auto-search all drives)"
    if (-not $vmdkInput) {
        Write-Host "  Auto-search selected - the script will scan common VM locations."
    }
    $vmLabel = Read-Host "Enter a label for this VM (e.g. VM1_Sleeping or VM2_Off)"
    if (-not $vmLabel) {
        if ($isSleeping) { $vmLabel = "VM${vmNumber}_Sleeping" }
        else { $vmLabel = "VM${vmNumber}_Off" }
    }

    $vmOutputPath = "$scriptRoot\Evidence\$vmLabel"
    New-Item -ItemType Directory -Path $vmOutputPath -Force | Out-Null

    # Start transcript BEFORE any work so prompts + output are captured
    $vmTranscript = "$scriptRoot\Transcript\${vmLabel}\transcript_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    New-Item -ItemType Directory -Path (Split-Path $vmTranscript) -Force | Out-Null
    Start-Transcript -Path $vmTranscript -Force

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting VM acquisition #$vmNumber : $vmLabel"
    Write-Host "  VM Type: $(if ($isSleeping) { 'Sleeping/Suspended (memory available)' } else { 'Switched Off (disk only)' })"

    # Run the acquisition function (handles VMDK search, .vmem copy, FTK imaging)
    Get-SleepingVMArtefacts -OutputPath $vmOutputPath `
                            -ScriptRoot $scriptRoot `
                            -VmLabel $vmLabel `
                            -VmdkPath $vmdkInput

    # --- Volatility / Strings analysis on .vmem (sleeping VM only) ---
    if ($isSleeping) {
        $vmemFiles = Get-ChildItem "$vmOutputPath" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(vmem|vmsn)$' }
        $vmemFile = $vmemFiles | Sort-Object Length -Descending | Select-Object -First 1

        if ($vmemFile) {
            Write-Host ""
            Write-Host "=========================================="
            Write-Host "  MEMORY ANALYSIS ON .VMEM (Criterion D)"
            Write-Host "=========================================="
            Write-Host "  Analysing: $($vmemFile.Name) ($([math]::Round($vmemFile.Length / 1MB, 1)) MB)"
            Write-Host "  Looking for: processes, network connections, files linking to second VM"
            Write-Host ""

            $vmMemAnalysis = Get-MemoryStrings -OutputPath $vmOutputPath `
                                               -RamDumpPath $vmemFile.FullName `
                                               -ScriptRoot $scriptRoot
            if ($vmMemAnalysis) {
                Write-Host "  Memory analysis results saved to: $vmOutputPath\memory_analysis\"
            }
        } else {
            Write-Host ""
            Write-Host "  NOTE: No .vmem file found in evidence - cannot run memory analysis."
            Write-Host "  This may mean the VM was shut down rather than suspended."
        }
    } else {
        Write-Host ""
        Write-Host "  NOTE: Switched-off VM - no live memory available."
        Write-Host "  Disk image will be analysed offline (mount E01 in FTK Imager)."
    }

    # Generate hashes of the acquired image files
    Write-Host ""
    Write-Host "=== Hashing acquired image files ==="
    $imageFiles = Get-ChildItem "$vmOutputPath" -Recurse -File -ErrorAction SilentlyContinue |
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
        $imageHashResults | Export-Csv "$vmOutputPath\image_hashes.csv" -NoTypeInformation -Encoding UTF8
    }
    Write-Host "Image hashes saved to: $vmOutputPath\image_hashes.csv"

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "VM #$vmNumber ($vmLabel) acquisition complete."
    Write-Host "Evidence: $vmOutputPath"
    Write-Host "=========================================="

    Stop-Transcript

} while ($true)
