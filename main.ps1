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

Write-Output "=========================================="
Write-Output "FORENSIC DATA COLLECTION"
Write-Output "=========================================="
Write-Output "Start Time : $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
Write-Output "VM Label   : $safeLabel"
Write-Output ""

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

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $registryHives  = Get-RegistryHives          -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $srumDb         = Get-SRUMDatabase           -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $amcache        = Get-AmcacheAndShimcache    -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $lnkFiles       = Get-LnkAndJumpLists       -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $thumbCache     = Get-ThumbnailCache        -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $mftUsn         = Get-MFTAndUsnJournal      -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Output ""

    # ========================================================================
    # PRIORITY 8: EMAILS AND MEMORY FILES
    # (variables used below in New-HTMLReport call)
    # ========================================================================
    Write-Output "PRIORITY 8: Email artefacts and memory files (pagefile/hiberfil)"
    Write-Output ""

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $emailArtefacts  = Get-EmailArtefacts         -OutputPath $evidencePath
    Write-Output ""
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    $memoryFiles     = Get-PagefileAndHiberfil    -OutputPath $evidencePath -ScriptRoot $scriptRoot
    Write-Output ""

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
                $hashes | Export-Csv "$evidencePath\hashes.csv" -NoTypeInformation
                Write-Output "Hashes saved to: $evidencePath\hashes.csv"
            }
        }
        Write-Output ""
    } else {
        Write-Output "Skipping file hashes"
        Write-Output ""
    }

    # ========================================================================
    # MEMORY STRING ANALYSIS (requires RAM dump)
    # ========================================================================
    $memoryStrings = $null
    if ($ramResult.Success -and $ramResult.Path) {
        $memoryStrings = Get-MemoryStrings -OutputPath $evidencePath -RamDumpPath $ramResult.Path
        Write-Output ""
    } else {
        Write-Output "Skipping memory string analysis (no RAM dump available)"
        Write-Output ""
    }

    # ========================================================================
    # HTML REPORT
    # ========================================================================
    New-HTMLReport -OutputPath $htmlReportPath `
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

    Stop-Transcript
}
