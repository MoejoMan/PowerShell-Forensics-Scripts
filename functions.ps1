Write-Host "Hello, World!"

# Forensic Collection Functions

# ============================================================================
# MEMORY ACQUISITION
# ============================================================================
# Acquires a physical memory (RAM) dump using WinPmem if available.
# Returns a PSCustomObject with `Success`, `Path`, and `Error` fields.
function Export-MemoryDump {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Dumping RAM ==="
    $result = [pscustomobject]@{
        Success = $false
        Path    = $null
        Error   = $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "WARNING: Not running as administrator; WinPmem may fail."
    }

    $candidatePaths = @(
        "bin\winpmem\go-winpmem_amd64_1.0-rc2_signed.exe",
        "bin\winpmem\winpmem_mini_x64_rc2.exe",
        "bin\go-winpmem_amd64_1.0-rc2_signed.exe",
        "go-winpmem_amd64_1.0-rc2_signed.exe"
    ) | ForEach-Object { Join-Path -Path $PSScriptRoot -ChildPath $_ }

    $winpmem = $candidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $winpmem) {
        Write-Host "ERROR: WinPmem not found. Checked:"
        $candidatePaths | ForEach-Object { Write-Host "  $_" }
        $result.Error = "WinPmem not found"
        return $result
    }

    try {
        $outputFile = Join-Path $OutputPath "memory_$(Get-Date -Format 'ddMMyyyy-HHmmss').raw"
        Write-Host "Acquiring memory... this may take a minute"
        Write-Host "Using WinPmem: $winpmem"

        $winpmemOutput = & $winpmem acquire --progress "$outputFile" 2>&1
        $exitCode = $LASTEXITCODE

        if ($winpmemOutput) {
            Write-Host "WinPmem output:"
            $winpmemOutput | ForEach-Object { Write-Host "  $_" }
        }

        if ($exitCode -ne 0) {
            $result.Error = "WinPmem exit code $exitCode"
            return $result
        }

        if (Test-Path $outputFile) {
            $result.Success = $true
            $result.Path = $outputFile
            Write-Host "RAM saved to: $outputFile"
            return $result
        }

        $result.Error = "WinPmem completed but no output file was created."
        return $result
    } catch {
        $result.Error = "ERROR dumping RAM: $_"
        return $result
    }
}

# ============================================================================
# LIVE SYSTEM COLLECTION
# ============================================================================
# Collects the current running processes, saves them to CSV, and returns the process objects.
function Get-ProcessList {
    param(
        [string]$OutputPath
    )
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Running Processes ==="
    try {
        $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path
        $processes | Format-Table -AutoSize
        $processes | Export-Csv "$OutputPath\processes.csv" -NoTypeInformation
        Write-Host "Processes saved to: $OutputPath\processes.csv"
        return $processes
    } catch {
        Write-Host "ERROR collecting processes: $_"
        return $null
    }
}

function Get-UserList {
    param(
        [string]$OutputPath
    )
    # Gathers local user accounts and exports them to CSV; returns the user objects.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Local User Accounts ==="
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon
        $users | Format-Table -AutoSize
        $users | Export-Csv "$OutputPath\users.csv" -NoTypeInformation
        Write-Host "Users saved to: $OutputPath\users.csv"
        return $users
    } catch {
        Write-Host "ERROR collecting users: $_"
        return $null
    }
}

function Get-NetworkConnections {
    param(
        [string]$OutputPath
    )
    # Captures current TCP connections (local/remote addresses and ports) and exports them to CSV.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting TCP Connections ==="
    try {
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
        $tcpConnections | Format-Table -AutoSize
        $tcpConnections | Export-Csv "$OutputPath\network_tcp.csv" -NoTypeInformation
        Write-Host "TCP connections saved to: $OutputPath\network_tcp.csv"
        return $tcpConnections
    } catch {
        Write-Host "ERROR collecting TCP connections: $_"
        return $null
    }
}

function Get-NetworkNeighbors {
    param(
        [string]$OutputPath
    )
    # Captures ARP/neighbor entries to map local network peers; exports to CSV.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Network Neighbors (ARP) ==="
    try {
        $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
        $neighbors | Format-Table -AutoSize
        $neighbors | Export-Csv "$OutputPath\network_neighbors.csv" -NoTypeInformation
        Write-Host "Network neighbors saved to: $OutputPath\network_neighbors.csv"
        return $neighbors
    } catch {
        Write-Host "ERROR collecting network neighbors: $_"
        return $null
    }
}

function Get-PrefetchFiles {
    param(
        [string]$OutputPath
    )
    # Enumerates Windows prefetch (.pf) files for recent program execution artefacts and exports to CSV.
    # Also copies the actual .pf files — they contain execution count, timestamps, and DLL/file references.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Prefetch Files ==="
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "WARNING: Not running as administrator; Prefetch access may be blocked."
    }
    try {
        $pfFiles = Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue
        $prefetch = $pfFiles | Select-Object Name, LastWriteTime, Length
        
        if ($prefetch) {
            $prefetch | Export-Csv "$OutputPath\prefetch.csv" -NoTypeInformation
            Write-Host "Prefetch metadata saved to: $OutputPath\prefetch.csv"

            # Copy actual .pf files — these contain execution counts, run timestamps,
            # and lists of files/DLLs loaded by each program. Parse with PECmd.exe.
            $pfDir = Join-Path $OutputPath "prefetch_files"
            New-Item -ItemType Directory -Path $pfDir -Force | Out-Null
            $copied = 0
            foreach ($pf in $pfFiles) {
                try {
                    Copy-Item $pf.FullName (Join-Path $pfDir $pf.Name) -Force -ErrorAction Stop
                    $copied++
                } catch {
                    # Prefetch files can sometimes be locked briefly
                    try {
                        & esentutl.exe /y /vss $pf.FullName /d (Join-Path $pfDir $pf.Name) 2>$null
                        if ($LASTEXITCODE -eq 0) { $copied++ }
                    } catch { }
                }
            }
            Write-Host "  Copied $copied / $($pfFiles.Count) .pf files -> $pfDir"
            Write-Host "  Parse with: PECmd.exe -d `"$pfDir`" --csv output_folder"
        } else {
            Write-Host "(No prefetch files found)"
        }
        return $prefetch
    } catch {
        Write-Host "ERROR collecting prefetch files: $_"
        return $null
    }
}

# ============================================================================
# HASHING AND INTEGRITY
# ============================================================================
# Computes SHA256 hashes for provided files and returns objects with name, path, size and SHA256.
function Get-FileHashes {
    param(
        [System.IO.FileInfo[]]$Files
    )

    if (-not $Files) {
        return @()
    }

    $hashes = foreach ($file in $Files) {
        try {
            $hash = Get-FileHash -Algorithm SHA256 -Path $file.FullName
            [pscustomobject]@{
                Name    = $file.Name
                Path    = $file.FullName
                SizeMB  = [math]::Round(($file.Length / 1MB), 2)
                SHA256  = $hash.Hash
            }
        } catch {
            [pscustomobject]@{
                Name    = $file.Name
                Path    = $file.FullName
                SizeMB  = [math]::Round(($file.Length / 1MB), 2)
                SHA256  = "ERROR: $_"
            }
        }
    }

    return $hashes
}

# ============================================================================
# HTML REPORTING
# ============================================================================
# Generates an HTML forensic report from collected artifact objects and writes it to the output path.
function New-HTMLReport {
    param(
        [string]$OutputPath,
        [object]$Processes,
        [object]$Users,
        [object]$TCPConnections,
        [object]$Neighbors,
        [object]$PrefetchFiles,
        [object]$InstalledPrograms,
        [object]$Services,
        [object]$ScheduledTasks,
        [object]$NetworkConfig,
        [object]$Autoruns,
        [object]$BrowserArtifacts,
        [object]$EventLogSecurity,
        [object]$EventLogSystem,
        [object]$EventLogApplication,
        [object]$WmiPersistence,
        [object]$RamResult,
        [object]$FileHashes,
        # â€” new sections â€”
        [object]$AlternateDataStreams,
        [object]$HiddenFiles,
        [object]$EncryptedVolumes,
        [object]$ZoneIdentifiers,
        [object]$RecentActivity,
        [object]$USBDevices,
        [object]$RecycleBin,
        [object]$DNSCache,
        [string]$ClipboardText,
        [object]$MappedDrives,
        [object]$PSHistory,
        [object]$RDPSessions,
        [object]$MemoryStrings,
        # --- deeper anti-forensics ---
        [object]$ShadowCopies,
        [object]$TimestompedFiles,
        [object]$UserAssist,
        [object]$HostsFileEntries,
        [object]$FirewallRules,
        [object]$DefenderExclusions,
        # --- deep-dive sections ---
        [object]$WiFiProfiles,
        [object]$WallpaperInfo,
        [object]$BrowserBookmarks,
        [object]$BrowserSearchHistory,
        [object]$WindowsTimeline,
        [object]$GameArtifacts,
        # --- Priority 7: Registry / Execution / File Metadata ---
        [object]$RegistryHives,
        [object]$SRUMDatabase,
        [object]$Amcache,
        [object]$LnkFiles,
        [object]$ThumbnailCache,
        [object]$MFTUsn,
        # --- Priority 8: Email & Memory Files ---
        [object]$EmailArtefacts,
        [object]$MemoryFiles
    )
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Generating HTML Report ==="
    
    try {
        # Convert objects to clean arrays, removing format objects
        if ($Processes) { $Processes = @($Processes | Where-Object { $_.Name -and ($null -ne $_.Id) } | Select-Object Name, Id, CPU, WorkingSet, Path) }
        if ($Users) { $Users = @($Users | Where-Object { $_.Name } | Select-Object Name, Enabled, Description, LastLogon) }
        if ($TCPConnections) { $TCPConnections = @($TCPConnections | Where-Object { $_.LocalAddress } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State) }
        if ($Neighbors) { $Neighbors = @($Neighbors | Where-Object { $_.IPAddress } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias) }
        if ($PrefetchFiles) { $PrefetchFiles = @($PrefetchFiles | Where-Object { $_.Name } | Select-Object Name, LastWriteTime, Length) }
        if ($InstalledPrograms) { $InstalledPrograms = @($InstalledPrograms | Where-Object { $_.DisplayName } | Select-Object DisplayName, Version, Publisher, InstallDate, SourceHive) }
        if ($Services) { $Services = @($Services | Where-Object { $_.Name } | Select-Object Name, DisplayName, Status, StartType) }
        if ($ScheduledTasks) { $ScheduledTasks = @($ScheduledTasks | Where-Object { $_.TaskName } | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Author, Principal, Actions) }
        if ($NetworkConfig) { $NetworkConfig = @($NetworkConfig | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, IPv4DefaultGateway) }
        if ($Autoruns) { $Autoruns = @($Autoruns | Where-Object { $_.Location -or $_.Name } | Select-Object Location, Name, Command, Source) }
        if ($EventLogSecurity) { $EventLogSecurity = @($EventLogSecurity | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($EventLogSystem) { $EventLogSystem = @($EventLogSystem | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($EventLogApplication) { $EventLogApplication = @($EventLogApplication | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($WmiPersistence) { $WmiPersistence = @($WmiPersistence | Where-Object { $_.Type -or $_.Name } | Select-Object Type, Name, QueryOrClass, Consumer, CommandLine, OtherFields) }

        # --- Filter new sections (strip Write-Host strings from pipeline) ---
        if ($AlternateDataStreams) { $AlternateDataStreams = @($AlternateDataStreams | Where-Object { $_.FilePath } | Select-Object FilePath, StreamName, StreamSize, FileModified) }
        if ($HiddenFiles) { $HiddenFiles = @($HiddenFiles | Where-Object { $_.FullPath } | Select-Object FullPath, Name, SizeKB, Attributes, Created, Modified) }
        if ($EncryptedVolumes) { $EncryptedVolumes = @($EncryptedVolumes | Where-Object { $_.Type } | Select-Object Type, Identifier, Status, Detail) }
        if ($ZoneIdentifiers) { $ZoneIdentifiers = @($ZoneIdentifiers | Where-Object { $_.FileName } | Select-Object FileName, FilePath, Zone, HostUrl, ReferrerUrl, FileSize, Modified) }
        if ($RecentActivity) { $RecentActivity = @($RecentActivity | Where-Object { $_.Source } | Select-Object Source, Name, Value, Modified) }
        if ($USBDevices) { $USBDevices = @($USBDevices | Where-Object { $_.DeviceClass } | Select-Object DeviceClass, SerialNumber, FriendlyName, Manufacturer, Driver, LastSeen) }
        if ($RecycleBin) { $RecycleBin = @($RecycleBin | Where-Object { $_.Name } | Select-Object Name, OriginalPath, Size, Type, DateDeleted) }
        if ($DNSCache) { $DNSCache = @($DNSCache | Where-Object { $_.Entry } | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data) }
        if ($MappedDrives) { $MappedDrives = @($MappedDrives | Where-Object { $_.Type } | Select-Object Type, Name, Root, UsedGB, FreeGB) }
        if ($PSHistory) { $PSHistory = @($PSHistory | Where-Object { $_.User } | Select-Object User, LineNum, Command, Source) }
        if ($RDPSessions) { $RDPSessions = @($RDPSessions | Where-Object { $_.Type } | Select-Object Type, Target, Username, Detail) }
        # --- New anti-forensic sections ---
        if ($ShadowCopies) { $ShadowCopies = @($ShadowCopies | Where-Object { $_.ShadowID -or $_.VolumeName } | Select-Object ShadowID, VolumeName, InstallDate, OriginMachine, ServiceMachine) }
        if ($TimestompedFiles) { $TimestompedFiles = @($TimestompedFiles | Where-Object { $_.FilePath } | Select-Object FilePath, Name, Created, Modified, DeltaHours, SizeKB) }
        if ($UserAssist) { $UserAssist = @($UserAssist | Where-Object { $_.ProgramName } | Select-Object ProgramName, RunCount, LastRun, FocusTime, Source) }
        if ($HostsFileEntries) { $HostsFileEntries = @($HostsFileEntries | Where-Object { $_.IP } | Select-Object IP, Hostname, Status) }
        if ($FirewallRules) { $FirewallRules = @($FirewallRules | Where-Object { $_.DisplayName } | Select-Object DisplayName, Direction, Action, Protocol, LocalPort, RemoteAddress, Enabled, Profile) }
        if ($DefenderExclusions) { $DefenderExclusions = @($DefenderExclusions | Where-Object { $_.Type } | Select-Object Type, Value, Risk) }
        if ($WiFiProfiles) { $WiFiProfiles = @($WiFiProfiles | Where-Object { $_.ProfileName } | Select-Object ProfileName, Authentication, Encryption, ConnectionMode, AutoConnect) }
        if ($WallpaperInfo) { $WallpaperInfo = @($WallpaperInfo | Where-Object { $_.Source } | Select-Object Source, Path, SizeKB, Modified) }
        if ($BrowserBookmarks) { $BrowserBookmarks = @($BrowserBookmarks | Where-Object { $_.Name } | Select-Object Browser, Folder, Name, URL) }
        if ($BrowserSearchHistory) { $BrowserSearchHistory = @($BrowserSearchHistory | Where-Object { $_.Query } | Select-Object Timestamp, Engine, Query) }
        if ($WindowsTimeline) { $WindowsTimeline = @($WindowsTimeline | Where-Object { $_.Application } | Select-Object Timestamp, Application, DisplayText, ActivityType) }
        if ($GameArtifacts) { $GameArtifacts = @($GameArtifacts | Where-Object { $_.Source } | Select-Object Source, Name, Detail, LastModified) }

        $downloads = $null
        $browserCopies = $null
        if ($BrowserArtifacts) {
            $downloads = @($BrowserArtifacts.Downloads)
            $browserCopies = @($BrowserArtifacts.BrowserCopies)
        }
        
        $ramStatus = "Not Attempted"
        $ramDetails = ""
        if ($RamResult) {
            if ($RamResult.Error -eq "Skipped") {
                $ramStatus = "Skipped"
                $ramDetails = "Disabled by operator"
            } elseif ($RamResult.Success -and $RamResult.Path -and (Test-Path $RamResult.Path)) {
                $ramItem = Get-Item $RamResult.Path
                $ramSizeMb = [math]::Round(($ramItem.Length / 1MB), 2)
                $ramStatus = "Success"
                $ramDetails = "${ramSizeMb} MB" 
            } elseif ($RamResult.Error) {
                $ramStatus = "Failed"
                $ramDetails = $RamResult.Error
            } else {
                $ramStatus = "Failed"
                $ramDetails = "Unknown error"
            }
        }

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 2px solid #34495e; padding-bottom: 5px; margin-top: 20px; }
        h3 { color: #2c3e50; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; background: white; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #ecf0f1; }
        details { margin: 15px 0; background: white; padding: 10px; border-radius: 5px; }
        summary { cursor: pointer; padding: 10px; background-color: #34495e; color: white; font-weight: bold; margin: -10px -10px 10px -10px; border-radius: 5px 5px 0 0; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 15px 0; }
        .card { background: white; padding: 12px; border-radius: 6px; border: 1px solid #dcdcdc; }
        .card h4 { margin: 0 0 6px 0; color: #2c3e50; font-size: 14px; }
        .card p { margin: 0; font-size: 13px; color: #2c3e50; }
        .muted { color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
<h1>Digital Forensic Report</h1>
<p class="timestamp">Generated: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')</p>
<p class="timestamp">Host: $env:COMPUTERNAME | User: $env:USERNAME</p>

<h3>Report Summary</h3>
<div class="summary">
    <div class="card"><h4>RAM Dump</h4><p>$ramStatus</p><p class="muted">$ramDetails</p></div>
    <div class="card"><h4>Processes</h4><p>$(@($Processes).Count)</p></div>
    <div class="card"><h4>Users</h4><p>$(@($Users).Count)</p></div>
    <div class="card"><h4>TCP Connections</h4><p>$(@($TCPConnections).Count)</p></div>
    <div class="card"><h4>Neighbors</h4><p>$(@($Neighbors).Count)</p></div>
    <div class="card"><h4>Prefetch</h4><p>$(@($PrefetchFiles).Count)</p></div>
    <div class="card"><h4>Installed Apps</h4><p>$(@($InstalledPrograms).Count)</p></div>
    <div class="card"><h4>Services</h4><p>$(@($Services).Count)</p></div>
    <div class="card"><h4>Tasks</h4><p>$(@($ScheduledTasks).Count)</p></div>
    <div class="card"><h4>Autoruns</h4><p>$(@($Autoruns).Count)</p></div>
    <div class="card"><h4>Downloads</h4><p>$(@($downloads).Count)</p></div>
    <div class="card"><h4>Security Events</h4><p>$(if ($EventLogSecurity -and $EventLogSecurity[0] -ne $null) { @($EventLogSecurity).Count } else { 0 })</p></div>
    <div class="card"><h4>WMI Bindings</h4><p>$(@($WmiPersistence).Count)</p></div>
    <div class="card"><h4>ADS Found</h4><p>$(@($AlternateDataStreams).Count)</p></div>
    <div class="card"><h4>Hidden Files</h4><p>$(@($HiddenFiles).Count)</p></div>
    <div class="card"><h4>USB Devices</h4><p>$(@($USBDevices).Count)</p></div>
    <div class="card"><h4>Recycle Bin</h4><p>$(@($RecycleBin).Count)</p></div>
    <div class="card"><h4>DNS Cache</h4><p>$(@($DNSCache).Count)</p></div>
    <div class="card"><h4>RDP Sessions</h4><p>$(@($RDPSessions).Count)</p></div>
    <div class="card"><h4>Memory IOCs</h4><p>$(@($MemoryStrings).Count)</p></div>
    <div class="card"><h4>Shadow Copies</h4><p>$(@($ShadowCopies).Count)</p></div>
    <div class="card"><h4>Timestomped</h4><p>$(@($TimestompedFiles).Count)</p></div>
    <div class="card"><h4>UserAssist</h4><p>$(@($UserAssist).Count)</p></div>
    <div class="card"><h4>Firewall Rules</h4><p>$(@($FirewallRules).Count)</p></div>
    <div class="card"><h4>Defender Excl.</h4><p>$(@($DefenderExclusions).Count)</p></div>
    <div class="card"><h4>Registry Hives</h4><p>$(if($RegistryHives){'Collected'}else{'N/A'})</p></div>
    <div class="card"><h4>SRUM DB</h4><p>$(if($SRUMDatabase){'Collected'}else{'N/A'})</p></div>
    <div class="card"><h4>Amcache</h4><p>$(if($Amcache){'Collected'}else{'N/A'})</p></div>
    <div class="card"><h4>LNK Files</h4><p>$(@($LnkFiles).Count)</p></div>
    <div class="card"><h4>Email Items</h4><p>$(@($EmailArtefacts).Count)</p></div>
    <div class="card"><h4>Memory Files</h4><p>$(@($MemoryFiles).Count)</p></div>
</div>

<details open>
    <summary>Collection Notes</summary>
    <p>This report contains volatile and non-volatile artifacts collected from a live system. Memory capture requires administrator access and may be blocked by security controls.</p>
    <p>Counts reflect the time of collection and may change between runs.</p>
</details>

<details>
    <summary>Scope and Limitations</summary>
    <ul>
        <li>Collection is limited to the artifacts gathered by this script and does not represent a full disk image.</li>
        <li>RAM capture is best-effort and may fail due to permissions or security controls.</li>
        <li>Network artifacts reflect a point-in-time snapshot and can change rapidly.</li>
        <li>Prefetch collection depends on Windows Prefetch being enabled.</li>
    </ul>
</details>

"@

        # Processes Section
        if ($Processes -and @($Processes).Count -gt 0) {
            $html += @"
<details open>
    <summary>Running Processes ($(@($Processes).Count) entries)</summary>
    $(@($Processes) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # Users Section
        if ($Users -and @($Users).Count -gt 0) {
            $html += @"
<details open>
    <summary>User Accounts ($(@($Users).Count) users)</summary>
    $(@($Users) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # Network Section
        if ((@($TCPConnections).Count -gt 0) -or (@($Neighbors).Count -gt 0)) {
            $html += "<details open><summary>Network Information</summary>"
            
            if (@($TCPConnections).Count -gt 0) {
                $html += @"
<h2>TCP Connections ($(@($TCPConnections).Count))</h2>
$(@($TCPConnections) | ConvertTo-Html -Fragment)
"@
            }
            
            if (@($Neighbors).Count -gt 0) {
                $html += @"
<h2>Network Neighbors / ARP ($(@($Neighbors).Count))</h2>
$(@($Neighbors) | ConvertTo-Html -Fragment)
"@
            }
            
            $html += "</details>"
        }

        # Prefetch Section
        if ($PrefetchFiles -and @($PrefetchFiles).Count -gt 0) {
            $html += @"
<details>
    <summary>Prefetch Files ($(@($PrefetchFiles).Count) files)</summary>
    $(@($PrefetchFiles) | ConvertTo-Html -Fragment)
</details>
"@
        } else {
            $html += @"
<details>
    <summary>Prefetch Files (0 files)</summary>
    <p>No prefetch files were collected. Run as administrator and ensure Windows Prefetch is enabled.</p>
</details>
"@
        }

        if ($InstalledPrograms -and @($InstalledPrograms).Count -gt 0) {
            $html += @"
<details>
    <summary>Installed Programs ($(@($InstalledPrograms).Count))</summary>
    $(@($InstalledPrograms) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($Services -and @($Services).Count -gt 0) {
            $html += @"
<details>
    <summary>Services ($(@($Services).Count))</summary>
    $(@($Services) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($ScheduledTasks -and @($ScheduledTasks).Count -gt 0) {
            $html += @"
<details>
    <summary>Scheduled Tasks ($(@($ScheduledTasks).Count))</summary>
    $(@($ScheduledTasks) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($NetworkConfig -and @($NetworkConfig).Count -gt 0) {
            $html += @"
<details>
    <summary>Network Configuration ($(@($NetworkConfig).Count))</summary>
    $(@($NetworkConfig) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($EventLogSecurity -or $EventLogSystem -or $EventLogApplication) {
            $html += "<details><summary>Event Logs (recent triage)</summary>"

            if ($EventLogSecurity -and @($EventLogSecurity).Count -gt 0 -and $EventLogSecurity[0] -ne $null) {
                $html += @"
<h2>Security Log ($(@($EventLogSecurity).Count))</h2>
$(@($EventLogSecurity) | ConvertTo-Html -Fragment)
"@
            } else {
                $html += @"
<h2>Security Log</h2>
<p><em>No security events captured. Security log may require audit policy to be enabled, or elevated privileges were insufficient. The raw .evtx file has been exported for offline analysis.</em></p>
"@
            }

            if (@($EventLogSystem).Count -gt 0) {
                $html += @"
<h2>System Log ($(@($EventLogSystem).Count))</h2>
$(@($EventLogSystem) | ConvertTo-Html -Fragment)
"@
            }

            if (@($EventLogApplication).Count -gt 0) {
                $html += @"
<h2>Application Log ($(@($EventLogApplication).Count))</h2>
$(@($EventLogApplication) | ConvertTo-Html -Fragment)
"@
            }

            $html += "</details>"
        }

        if ($Autoruns -and @($Autoruns).Count -gt 0) {
            $html += @"
<details>
    <summary>Autoruns ($(@($Autoruns).Count))</summary>
    $(@($Autoruns) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($downloads -and @($downloads).Count -gt 0) {
            $html += @"
<details>
    <summary>Downloads Folder ($(@($downloads).Count) files)</summary>
    $(@($downloads) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($WmiPersistence -and @($WmiPersistence).Count -gt 0) {
            $html += @"
<details>
    <summary>WMI Persistence ($(@($WmiPersistence).Count))</summary>
    $(@($WmiPersistence) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($browserCopies -and @($browserCopies).Count -gt 0) {
            $html += @"
<details>
    <summary>Browser Artifacts Copy Status ($(@($browserCopies).Count))</summary>
    $(@($browserCopies) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # ====== NEW SECTIONS ======

        if ($ZoneIdentifiers -and @($ZoneIdentifiers).Count -gt 0) {
            $html += @"
<details open>
    <summary>Download Origins / Zone.Identifier ($(@($ZoneIdentifiers).Count) files)</summary>
    <p><em>Shows where files were downloaded from (HostUrl) and the referring page. Zone 3 = Internet.</em></p>
    $(@($ZoneIdentifiers) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($AlternateDataStreams -and @($AlternateDataStreams).Count -gt 0) {
            $html += @"
<details open>
    <summary>Alternate Data Streams ($(@($AlternateDataStreams).Count) - SUSPICIOUS)</summary>
    <p><em>NTFS Alternate Data Streams can hide data inside normal files without changing their visible size. Any entries here warrant further examination.</em></p>
    $(@($AlternateDataStreams) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($HiddenFiles -and @($HiddenFiles).Count -gt 0) {
            $html += @"
<details>
    <summary>Hidden &amp; System Files ($(@($HiddenFiles).Count))</summary>
    <p><em>Files with Hidden or System attributes set in user-writable directories.</em></p>
    $(@($HiddenFiles) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($EncryptedVolumes -and @($EncryptedVolumes).Count -gt 0) {
            $html += @"
<details open>
    <summary>Encrypted Volumes &amp; Containers ($(@($EncryptedVolumes).Count))</summary>
    <p><em>BitLocker volumes, VeraCrypt / TrueCrypt containers, and related running processes.</em></p>
    $(@($EncryptedVolumes) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($USBDevices -and @($USBDevices).Count -gt 0) {
            $html += @"
<details open>
    <summary>USB Device History ($(@($USBDevices).Count))</summary>
    <p><em>USB storage devices previously connected. May indicate data exfiltration.</em></p>
    $(@($USBDevices) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($RecycleBin -and @($RecycleBin).Count -gt 0) {
            $html += @"
<details open>
    <summary>Recycle Bin ($(@($RecycleBin).Count) items)</summary>
    <p><em>Deleted files may contain evidence the suspect tried to destroy.</em></p>
    $(@($RecycleBin) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($RecentActivity -and @($RecentActivity).Count -gt 0) {
            $html += @"
<details>
    <summary>Recent File Activity / MRU ($(@($RecentActivity).Count))</summary>
    <p><em>Recent documents opened, paths typed in Explorer, and Run dialog history.</em></p>
    $(@($RecentActivity) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($DNSCache -and @($DNSCache).Count -gt 0) {
            $html += @"
<details>
    <summary>DNS Cache ($(@($DNSCache).Count) entries)</summary>
    <p><em>Recently resolved domain names (volatile - lost on reboot).</em></p>
    $(@($DNSCache) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($ClipboardText) {
            $escapedClip = [System.Net.WebUtility]::HtmlEncode($ClipboardText)
            $html += @"
<details open>
    <summary>Clipboard Contents</summary>
    <p><em>Text data on the clipboard at time of collection (volatile).</em></p>
    <pre style="background:#fff;padding:12px;border:1px solid #bdc3c7;white-space:pre-wrap;">$escapedClip</pre>
</details>
"@
        }

        if ($MappedDrives -and @($MappedDrives).Count -gt 0) {
            $html += @"
<details open>
    <summary>Mapped Drives &amp; Network Shares ($(@($MappedDrives).Count))</summary>
    <p><em>Network-mapped drives, SMB shares hosted, and active inbound sessions.</em></p>
    $(@($MappedDrives) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($PSHistory -and @($PSHistory).Count -gt 0) {
            $html += @"
<details>
    <summary>PowerShell Command History ($(@($PSHistory).Count) commands)</summary>
    <p><em>Commands previously executed in PowerShell by each user (PSReadLine history).</em></p>
    $(@($PSHistory) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($RDPSessions -and @($RDPSessions).Count -gt 0) {
            $html += @"
<details open>
    <summary>RDP &amp; Remote Sessions ($(@($RDPSessions).Count))</summary>
    <p><em>Remote Desktop connections (outgoing history, cache files, active sessions). Critical for linking two VMs.</em></p>
    $(@($RDPSessions) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($MemoryStrings -and @($MemoryStrings).Count -gt 0) {
            if ($MemoryStrings) { $MemoryStrings = @($MemoryStrings | Where-Object { $_.Source } | Select-Object Source, Plugin, Detail, File) }
            $html += @"
<details open>
    <summary>Memory Analysis — Volatility &amp; Strings ($(@($MemoryStrings).Count) IOC categories)</summary>
    <p><em>Automated memory analysis results. Volatility 3 plugin output and strings extraction for emails, IPs, URLs, UNC paths, bitcoin addresses, and password references. Full output files are in the <code>memory_analysis</code> subfolder.</em></p>
    $(@($MemoryStrings) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # ====== DEEPER ANTI-FORENSICS SECTIONS ======

        if ($ShadowCopies -and @($ShadowCopies).Count -gt 0) {
            $html += @"
<details open>
    <summary>Volume Shadow Copies ($(@($ShadowCopies).Count))</summary>
    <p><em>Shadow copies can contain older versions of files the suspect may have deleted or modified. Absence of expected shadow copies may indicate vssadmin delete shadows was used.</em></p>
    $(@($ShadowCopies) | ConvertTo-Html -Fragment)
</details>
"@
        } else {
            $html += @"
<details open>
    <summary>Volume Shadow Copies (0)</summary>
    <p><em>No shadow copies found. This may indicate the suspect ran <code>vssadmin delete shadows /all</code> to destroy recovery points.</em></p>
</details>
"@
        }

        if ($TimestompedFiles -and @($TimestompedFiles).Count -gt 0) {
            $html += @"
<details open>
    <summary>Timestomp Detection ($(@($TimestompedFiles).Count) anomalies)</summary>
    <p><em>Files where the Creation timestamp is LATER than the Modified timestamp. This is impossible under normal use and is a strong indicator of timestamp manipulation (anti-forensic technique).</em></p>
    $(@($TimestompedFiles) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($UserAssist -and @($UserAssist).Count -gt 0) {
            $html += @"
<details>
    <summary>UserAssist Program Execution ($(@($UserAssist).Count))</summary>
    <p><em>Windows tracks GUI program launches in the UserAssist registry key (ROT13 encoded). Shows what applications the suspect ran and how many times.</em></p>
    $(@($UserAssist) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($HostsFileEntries -and @($HostsFileEntries).Count -gt 0) {
            $html += @"
<details open>
    <summary>Hosts File Analysis ($(@($HostsFileEntries).Count) entries)</summary>
    <p><em>The hosts file can redirect domain names to different IPs. Attackers modify it to block security updates, redirect banking sites, or hide C2 traffic.</em></p>
    $(@($HostsFileEntries) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($FirewallRules -and @($FirewallRules).Count -gt 0) {
            $html += @"
<details>
    <summary>Custom Firewall Rules ($(@($FirewallRules).Count))</summary>
    <p><em>Firewall rules that allow inbound connections or were recently created. Attackers may add rules to permit reverse shells or C2 channels.</em></p>
    $(@($FirewallRules) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($DefenderExclusions -and @($DefenderExclusions).Count -gt 0) {
            $html += @"
<details open>
    <summary>Windows Defender Exclusions ($(@($DefenderExclusions).Count) - SUSPICIOUS)</summary>
    <p><em>Defender exclusions prevent scanning of specified paths, processes, or extensions. Attackers add exclusions to hide malware from detection.</em></p>
    $(@($DefenderExclusions) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # --- New deep-dive sections ---
        if ($WiFiProfiles -and @($WiFiProfiles).Count -gt 0) {
            $html += @"
<details>
    <summary>Saved WiFi Profiles ($(@($WiFiProfiles).Count))</summary>
    <p><em>All wireless networks the device has connected to. Reveals locations visited, personal hotspots used, and network history.</em></p>
    $(@($WiFiProfiles) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($WallpaperInfo -and @($WallpaperInfo).Count -gt 0) {
            $html += @"
<details>
    <summary>Desktop Wallpaper &amp; Theme ($(@($WallpaperInfo).Count))</summary>
    <p><em>Current and cached desktop wallpaper information. Can reveal personal interests or inappropriate imagery.</em></p>
    $(@($WallpaperInfo) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($BrowserBookmarks -and @($BrowserBookmarks).Count -gt 0) {
            $html += @"
<details>
    <summary>Browser Bookmarks ($(@($BrowserBookmarks).Count))</summary>
    <p><em>Saved bookmarks from Chrome and Edge browsers. Shows intentionally saved pages - stronger indicator of interest than browsing history.</em></p>
    $(@($BrowserBookmarks) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($BrowserSearchHistory -and @($BrowserSearchHistory).Count -gt 0) {
            $html += @"
<details>
    <summary>Browser Search History ($(@($BrowserSearchHistory).Count) queries)</summary>
    <p><em>Google and Bing search queries extracted from browser URL history. Reveals the user's intentions, interests, and investigative behaviour.</em></p>
    $(@($BrowserSearchHistory) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($WindowsTimeline -and @($WindowsTimeline).Count -gt 0) {
            $html += @"
<details>
    <summary>Windows Activity Timeline ($(@($WindowsTimeline).Count))</summary>
    <p><em>Windows Activity History from ActivitiesCache.db. Tracks which applications were used and when, including focus time.</em></p>
    $(@($WindowsTimeline) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($GameArtifacts -and @($GameArtifacts).Count -gt 0) {
            $html += @"
<details>
    <summary>Game &amp; Entertainment Artifacts ($(@($GameArtifacts).Count))</summary>
    <p><em>Evidence of gaming activity from Steam, Rimworld, Minecraft, and other sources. Shows entertainment habits and time usage.</em></p>
    $(@($GameArtifacts) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # ====== PRIORITY 7: REGISTRY / EXECUTION / FILE METADATA ======

        if ($RegistryHives) {
            $html += @"
<details open>
    <summary>Registry Hives (Priority 7)</summary>
    <p><em>Binary registry hive exports (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat). These contain user accounts, password hashes, USB history, installed software, autorun entries, MRU lists, and typed paths. Parse with Registry Explorer or RegRipper.</em></p>
    <p><strong>Collected to:</strong> $RegistryHives</p>
    <p><strong>Key hives:</strong></p>
    <ul>
        <li><strong>SAM</strong> — Local user accounts and password hashes</li>
        <li><strong>SYSTEM</strong> — Hardware config, timezone, USB history, network interfaces</li>
        <li><strong>SOFTWARE</strong> — Installed programs, autorun entries, OS settings</li>
        <li><strong>SECURITY</strong> — LSA secrets, cached credentials</li>
        <li><strong>NTUSER.DAT</strong> — Per-user settings, MRU lists, typed paths, UserAssist</li>
        <li><strong>UsrClass.dat</strong> — User-specific COM/shell settings, folder access (ShellBags)</li>
    </ul>
</details>
"@
        }

        if ($SRUMDatabase) {
            $html += @"
<details>
    <summary>SRUM Database (Priority 7)</summary>
    <p><em>System Resource Usage Monitor — records per-application network bytes sent/received, CPU time, and energy usage with timestamps going back ~30 days. Persists even after browser history is cleared. Can prove network exfiltration activity.</em></p>
    <p><strong>Collected to:</strong> $SRUMDatabase</p>
    <p><strong>Parse with:</strong> SrumECmd.exe (Eric Zimmermann) or srum-dump</p>
</details>
"@
        }

        if ($Amcache) {
            $html += @"
<details>
    <summary>Amcache &amp; ShimCache (Priority 7)</summary>
    <p><em>Amcache.hve records SHA1 hashes of every executable run on the system, even if the file has since been deleted. Critical for proving a program was executed. ShimCache (AppCompatCache) in SYSTEM hive records execution order and timestamps.</em></p>
    <p><strong>Collected to:</strong> $Amcache</p>
    <p><strong>Parse with:</strong> AmcacheParser.exe / AppCompatCacheParser.exe (Eric Zimmermann)</p>
</details>
"@
        }

        if ($LnkFiles -and @($LnkFiles).Count -gt 0) {
            if ($LnkFiles) { $LnkFiles = @($LnkFiles | Where-Object { $_.LnkName } | Select-Object User, Type, LnkName, TargetPath, LnkCreated, LnkModified) }
            $html += @"
<details>
    <summary>LNK Files &amp; Jump Lists ($(@($LnkFiles).Count) metadata entries) (Priority 7)</summary>
    <p><em>LNK shortcut files are created automatically when files are opened. They contain the original file path, MAC timestamps, and volume serial number — even if the original file no longer exists. Jump Lists extend this with per-application MRU lists.</em></p>
    <p><strong>Parse with:</strong> LECmd.exe and JLECmd.exe (Eric Zimmermann)</p>
    $(@($LnkFiles) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($ThumbnailCache) {
            $html += @"
<details>
    <summary>Thumbnail Cache (Priority 7)</summary>
    <p><em>Windows caches thumbnails of viewed images, videos, and documents. These can retain thumbnails of files that have since been deleted — potentially showing images the suspect viewed even after they cleared downloads or recycle bin.</em></p>
    <p><strong>Collected to:</strong> $ThumbnailCache</p>
    <p><strong>Parse with:</strong> Thumbcache Viewer — https://thumbcacheviewer.github.io</p>
</details>
"@
        }

        if ($MFTUsn) {
            $html += @"
<details>
    <summary>MFT &amp; USN Journal (Priority 7)</summary>
    <p><em>The Master File Table (`$MFT) is the index of every file on an NTFS volume — deleted entries persist until overwritten. The USN Change Journal records every file system operation (create, modify, rename, delete).</em></p>
    <p><strong>Collected to:</strong> $MFTUsn</p>
    <p><strong>Parse with:</strong> MFTECmd.exe (Eric Zimmermann) for timeline analysis</p>
</details>
"@
        }

        # ====== PRIORITY 8: EMAIL & MEMORY FILES ======

        if ($EmailArtefacts -and @($EmailArtefacts).Count -gt 0) {
            if ($EmailArtefacts) { $EmailArtefacts = @($EmailArtefacts | Where-Object { $_.FileName } | Select-Object User, Type, FileName, SourcePath, SizeMB, Modified, CopyStatus) }
            $html += @"
<details open>
    <summary>Email Artefacts ($(@($EmailArtefacts).Count) items) (Priority 8)</summary>
    <p><em>Outlook PST/OST files, Thunderbird mbox folders, and Windows Mail data. PST/OST files contain the full mailbox including deleted items. Email headers contain IP addresses and timestamps for attribution.</em></p>
    <p><strong>Analysis tips:</strong></p>
    <ul>
        <li>PST/OST: Open in Outlook, or use free Kernel PST Viewer</li>
        <li>MBOX: Open in Thunderbird, or use readpst on Linux</li>
        <li>Check: Deleted Items, Sent Items, Drafts for unsent messages</li>
        <li>Email headers contain originating IP addresses</li>
    </ul>
    $(@($EmailArtefacts) | ConvertTo-Html -Fragment)
</details>
"@
        }

        if ($MemoryFiles -and @($MemoryFiles).Count -gt 0) {
            if ($MemoryFiles) { $MemoryFiles = @($MemoryFiles | Where-Object { $_.File } | Select-Object File, SizeMB, Status, Description, Method) }
            $html += @"
<details open>
    <summary>Memory Files — Pagefile / Hiberfil ($(@($MemoryFiles).Count) targets) (Priority 8)</summary>
    <p><em>pagefile.sys contains RAM fragments (passwords, documents, network data). hiberfil.sys is a full RAM snapshot from hibernation — parse with Volatility as a memory image. swapfile.sys contains UWP app swap data.</em></p>
    <p><strong>Analysis tips:</strong></p>
    <ul>
        <li>hiberfil.sys: <code>vol.py -f hiberfil.sys windows.pslist</code></li>
        <li>pagefile.sys: <code>strings.exe -n 8 pagefile.sys | findstr /i "password"</code></li>
    </ul>
    $(@($MemoryFiles) | ConvertTo-Html -Fragment)
</details>
"@
        }

        # Hashes Section
        if ($FileHashes -and @($FileHashes).Count -gt 0) {
            $html += @"
<details>
    <summary>File Hashes ($(@($FileHashes).Count) files)</summary>
    $(@($FileHashes) | ConvertTo-Html -Fragment)
</details>
"@
        }

        $html += @"
</body>
</html>
"@

        $reportPath = "$OutputPath\forensic_report.html"
        $html | Out-File $reportPath -Encoding UTF8
        Write-Host "HTML report saved to: $reportPath"
    } catch {
        Write-Host "ERROR generating HTML report: $_"
    }
}

function Get-InstalledPrograms {
    param(
        [string]$OutputPath
    )
    # Enumerates installed applications (registry + Appx) and exports a CSV listing.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Installed Programs ==="
    try {
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $programs = foreach ($path in $uninstallPaths) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    DisplayName = $_.DisplayName
                    Version     = $_.DisplayVersion
                    Publisher   = $_.Publisher
                    InstallDate = $_.InstallDate
                    Uninstall   = $_.UninstallString
                    SourceHive  = $path
                }
            }
        }

        $appx = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object Name, Version, Publisher, InstallLocation

        $all = @()
        if ($programs) { $all += $programs }
        if ($appx) {
            $all += ($appx | ForEach-Object {
                [pscustomobject]@{
                    DisplayName = $_.Name
                    Version     = $_.Version
                    Publisher   = $_.Publisher
                    InstallDate = $null
                    Uninstall   = $null
                    SourceHive  = 'Appx'
                }
            })
        }

        if ($all.Count -gt 0) {
            $all | Export-Csv "$OutputPath\installed_programs.csv" -NoTypeInformation
            Write-Host "Installed programs saved to: $OutputPath\installed_programs.csv"
        } else {
            Write-Host "(No installed programs found)"
        }
        return $all
    } catch {
        Write-Host "ERROR collecting installed programs: $_"
        return $null
    }
}

function Get-ServicesList {
    param(
        [string]$OutputPath
    )
    # Lists Windows services and exports basic status and configuration to CSV.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Services ==="
    try {
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
        if ($services) {
            $services | Export-Csv "$OutputPath\services.csv" -NoTypeInformation
            Write-Host "Services saved to: $OutputPath\services.csv"
        }
        return $services
    } catch {
        Write-Host "ERROR collecting services: $_"
        return $null
    }
}

function Get-ScheduledTasksList {
    param(
        [string]$OutputPath
    )
    # Retrieves scheduled tasks, their last/next run times and actions, then exports to CSV.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Scheduled Tasks ==="
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName      = $_.TaskName
                TaskPath      = $_.TaskPath
                State         = $_.State
                LastRunTime   = $info.LastRunTime
                NextRunTime   = $info.NextRunTime
                Author        = $_.Author
                Principal     = ($_.Principal.UserId)
                Actions       = ($_.Actions | ForEach-Object { $_.Execute }) -join '; '
            }
        }

        if ($tasks) {
            $tasks | Export-Csv "$OutputPath\tasks.csv" -NoTypeInformation
            Write-Host "Scheduled tasks saved to: $OutputPath\tasks.csv"
        }
        return $tasks
    } catch {
        Write-Host "ERROR collecting scheduled tasks: $_"
        return $null
    }
}

function Get-NetworkConfig {
    param(
        [string]$OutputPath
    )
    # Captures network adapter configuration (IP addresses, DNS, gateways) and exports to CSV.
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Network Configuration ==="
    try {
        $adapters = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, IPv4DefaultGateway
        if ($adapters) {
            $adapters | Export-Csv "$OutputPath\network_config.csv" -NoTypeInformation
            Write-Host "Network configuration saved to: $OutputPath\network_config.csv"
        }
        return $adapters
    } catch {
        Write-Host "ERROR collecting network configuration: $_"
        return $null
    }
}

function Get-EventLogTriage {
    param(
        [string]$OutputPath,
        [int]$Days = 3
    )

        # Collects recent events from Security, System, and Application logs (default last 3 days) and exports CSVs.
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Event Log Triage ==="
    $logs = @{
        Security    = 'event_security.csv'
        System      = 'event_system.csv'
        Application = 'event_application.csv'
    }

    $results = @{}

    $startTime = (Get-Date).AddDays(-$Days)

    foreach ($logName in $logs.Keys) {
        $target = Join-Path $OutputPath $logs[$logName]
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $startTime
            } -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

            if ($events) {
                $events | Export-Csv $target -NoTypeInformation
                Write-Host "$logName events saved to: $target"
            } else {
                Write-Host "(No $logName events found in last $Days days)"
            }

            $results[$logName] = $events
        } catch {
            Write-Host "ERROR collecting $logName log: $_"
            $results[$logName] = $null
        }
    }

    return [pscustomobject]@{
        Security    = $results.Security
        System      = $results.System
        Application = $results.Application
    }
}

function Get-WmiPersistence {
    param(
        [string]$OutputPath
    )

        # Collects WMI persistence artifacts (filters, consumers, and bindings) to detect persistent techniques.
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting WMI persistence (filters/consumers/bindings) ==="
    $items = @()

    try {
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        foreach ($f in $filters) {
            $items += [pscustomobject]@{
                Type        = 'EventFilter'
                Name        = $f.Name
                QueryOrClass= $f.Query
                Consumer    = $null
                CommandLine = $null
                OtherFields = $f.EventNamespace
            }
        }
    } catch {
        Write-Host "WARNING: Failed reading __EventFilter - $_"
    }

    try {
        $cmdConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
        foreach ($c in $cmdConsumers) {
            $items += [pscustomobject]@{
                Type        = 'CommandLineEventConsumer'
                Name        = $c.Name
                QueryOrClass= $null
                Consumer    = $c.Name
                CommandLine = $c.CommandLineTemplate
                OtherFields = $c.WorkingDirectory
            }
        }
    } catch {
        Write-Host "WARNING: Failed reading CommandLineEventConsumer - $_"
    }

    try {
        $scriptConsumers = Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        foreach ($c in $scriptConsumers) {
            $items += [pscustomobject]@{
                Type        = 'ActiveScriptEventConsumer'
                Name        = $c.Name
                QueryOrClass= $null
                Consumer    = $c.Name
                CommandLine = $c.ScriptText
                OtherFields = $c.ScriptingEngine
            }
        }
    } catch {
        Write-Host "WARNING: Failed reading ActiveScriptEventConsumer - $_"
    }

    try {
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($b in $bindings) {
            $items += [pscustomobject]@{
                Type        = 'FilterToConsumerBinding'
                Name        = $b.Name
                QueryOrClass= $b.Filter
                Consumer    = $b.Consumer
                CommandLine = $null
                OtherFields = $b.DeliveryQoS
            }
        }
    } catch {
        Write-Host "WARNING: Failed reading __FilterToConsumerBinding - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\wmi_persistence.csv" -NoTypeInformation
        Write-Host "WMI persistence saved to: $OutputPath\wmi_persistence.csv"
    } else {
        Write-Host "(No WMI persistence entries found)"
    }

    return $items
}

function Get-Autoruns {
    param(
        [string]$OutputPath
    )
        # Enumerates autorun entries from registry Run keys and standard Startup folders; exports findings to CSV.
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Autoruns (Run keys & Startup folders) ==="
    $items = @()

    $runPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($path in $runPaths) {
        if (Test-Path $path) {
            try {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    $items += [pscustomobject]@{
                        Location = $path
                        Name     = $_.Name
                        Command  = $_.Value
                        Source   = 'Registry'
                    }
                }
            } catch {
                Write-Host "WARNING: Failed to read $path - $_"
            }
        }
    }

    $startupDirs = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($dir in $startupDirs) {
        if (Test-Path $dir) {
            try {
                Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $items += [pscustomobject]@{
                        Location = $dir
                        Name     = $_.Name
                        Command  = $_.FullName
                        Source   = 'StartupFolder'
                    }
                }
            } catch {
                Write-Host "WARNING: Failed to read $dir - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\autoruns.csv" -NoTypeInformation
        Write-Host "Autoruns saved to: $OutputPath\autoruns.csv"
    } else {
        Write-Host "(No autoruns found)"
    }
    return $items
}

# ============================================================================
# ANTI-FORENSICS & CONCEALMENT DETECTION
# ============================================================================

# Scans user-accessible areas for NTFS Alternate Data Streams (hidden data
# attached to regular files).  Commonly abused to conceal payloads, exfil
# lists, or extortion material without changing visible file properties.
function Get-AlternateDataStreams {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Scanning for Alternate Data Streams (ADS) ==="
    $items = @()

    # Directories most likely to contain user-planted ADS
    $scanPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "C:\Temp",
        "C:\Users\Public"
    )

    foreach ($dir in $scanPaths) {
        if (-not (Test-Path $dir)) { continue }
        try {
            # Get-Item -Stream * lists every stream; Zone.Identifier is normal,
            # but anything beyond :$DATA and Zone.Identifier is suspicious.
            # Depth-limited to 5 to balance coverage vs performance.
            Get-ChildItem -Path $dir -Recurse -Depth 5 -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $file = $_
                    try {
                        $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue |
                            Where-Object {
                                $_.Stream -ne ':$DATA' -and
                                $_.Stream -ne 'Zone.Identifier' -and
                                $_.Stream -notmatch '^MBAM\.Zone\.Identifier$' -and
                                $_.Stream -notmatch '^SmartScreen$'
                            }
                        foreach ($s in $streams) {
                            $items += [pscustomobject]@{
                                FilePath   = $file.FullName
                                StreamName = $s.Stream
                                StreamSize = $s.Length
                                FileModified = $file.LastWriteTime
                            }
                        }
                    } catch { }
                }
        } catch {
            Write-Host "WARNING: ADS scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\alternate_data_streams.csv" -NoTypeInformation
        Write-Host "ADS results saved to: $OutputPath\alternate_data_streams.csv"
    } else {
        Write-Host "(No suspicious alternate data streams found)"
    }
    return $items
}

# Enumerates hidden and system files in user-writable directories.
# Attackers frequently set the Hidden or System attribute to conceal
# tools, key-loggers, or stolen data from casual browsing.
function Get-HiddenFiles {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Scanning for Hidden & System Files ==="
    $items = @()

    $scanPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "C:\Temp",
        "C:\Users\Public"
    )

    foreach ($dir in $scanPaths) {
        if (-not (Test-Path $dir)) { continue }
        try {
            # Depth-limited to 5 to balance coverage vs performance.
            Get-ChildItem -Path $dir -Recurse -Depth 5 -Force -File -ErrorAction SilentlyContinue |
                Where-Object {
                    (($_.Attributes -band [System.IO.FileAttributes]::Hidden) -or
                     ($_.Attributes -band [System.IO.FileAttributes]::System)) -and
                    # Exclude known-benign Windows hidden/system files
                    $_.Name -ne 'desktop.ini' -and
                    $_.Name -notmatch '^~\$' -and                             # Office temp/lock files
                    $_.FullName -notmatch 'AccountPictures' -and              # Windows profile pictures
                    $_.FullName -notmatch 'AppData\\Local\\Microsoft' -and  # System cache
                    $_.FullName -notmatch 'AppData\\Local\\Packages'        # UWP app data
                } | ForEach-Object {
                    $items += [pscustomobject]@{
                        FullPath       = $_.FullName
                        Name           = $_.Name
                        SizeKB         = [math]::Round(($_.Length / 1KB), 2)
                        Attributes     = $_.Attributes.ToString()
                        Created        = $_.CreationTime
                        Modified       = $_.LastWriteTime
                    }
                }
        } catch {
            Write-Host "WARNING: Hidden-file scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\hidden_files.csv" -NoTypeInformation
        Write-Host "Hidden files saved to: $OutputPath\hidden_files.csv"
    } else {
        Write-Host "(No hidden/system files found in scanned paths)"
    }
    return $items
}

# Detects presence of disk-encryption tools (BitLocker, VeraCrypt,
# TrueCrypt) and containers.  Encrypted volumes may hide stolen data
# or extortion-related material from forensic examination.
function Get-EncryptedVolumeDetection {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Detecting Encrypted Volumes & Containers ==="
    $items = @()

    # BitLocker status
    try {
        $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue
        foreach ($v in $bl) {
            $items += [pscustomobject]@{
                Type       = 'BitLocker'
                Identifier = $v.MountPoint
                Status     = $v.ProtectionStatus
                Detail     = $v.EncryptionMethod
            }
        }
    } catch {
        Write-Host "WARNING: BitLocker query failed (may not be available) - $_"
    }

    # Look for VeraCrypt / TrueCrypt containers by extension or known process
    $containerExts = @('*.hc', '*.tc', '*.vhd', '*.vhdx', '*.img')
    $searchDirs = @("$env:USERPROFILE", "C:\Users\Public", "C:\Temp")
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($ext in $containerExts) {
            Get-ChildItem -Path $dir -Filter $ext -Recurse -Depth 5 -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Type       = 'Container'
                    Identifier = $_.FullName
                    Status     = "$([math]::Round($_.Length / 1MB, 2)) MB"
                    Detail     = "Extension: $($_.Extension)"
                }
            }
        }
    }

    # Running encryption processes
    $encProcs = Get-Process -Name 'VeraCrypt','TrueCrypt','veracrypt','truecrypt' -ErrorAction SilentlyContinue
    foreach ($p in $encProcs) {
        $items += [pscustomobject]@{
            Type       = 'RunningProcess'
            Identifier = $p.Name
            Status     = "PID $($p.Id)"
            Detail     = $p.Path
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\encrypted_volumes.csv" -NoTypeInformation
        Write-Host "Encrypted volume info saved to: $OutputPath\encrypted_volumes.csv"
    } else {
        Write-Host "(No encrypted volumes or containers detected)"
    }
    return $items
}

# ============================================================================
# FILE PROVENANCE & METADATA
# ============================================================================

# Reads NTFS Zone.Identifier ADS to determine WHERE files were downloaded
# from, e.g. which URL / referrer.  Critical for linking downloaded tools
# or stolen data back to an extortion method (email attachment, web drop).
function Get-ZoneIdentifierInfo {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Zone.Identifier (Download Origins) ==="
    $items = @()

    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "C:\Temp",
        "C:\Users\Public\Downloads"
    )

    foreach ($dir in $scanPaths) {
        if (-not (Test-Path $dir)) { continue }
        try {
            # Depth-limited to 4 to balance coverage vs performance.
            Get-ChildItem -Path $dir -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $zi = Get-Content -Path $_.FullName -Stream Zone.Identifier -ErrorAction Ignore 2>$null
                    if ($zi) {
                        $zoneMatch = $zi | Select-String 'ZoneId=(\d)'
                        $zoneId    = if ($zoneMatch) { $zoneMatch.Matches[0].Groups[1].Value } else { $null }
                        $hostMatch = $zi | Select-String 'HostUrl=(.+)'
                        $hostUrl   = if ($hostMatch) { $hostMatch.Matches[0].Groups[1].Value } else { $null }
                        $refMatch  = $zi | Select-String 'ReferrerUrl=(.+)'
                        $referrer  = if ($refMatch)  { $refMatch.Matches[0].Groups[1].Value } else { $null }

                        $zoneName = switch ($zoneId) {
                            '0' { 'Local'   }
                            '1' { 'Intranet'}
                            '2' { 'Trusted' }
                            '3' { 'Internet'}
                            '4' { 'Restricted'}
                            default { "Unknown ($zoneId)" }
                        }

                        $items += [pscustomobject]@{
                            FileName    = $_.Name
                            FilePath    = $_.FullName
                            Zone        = $zoneName
                            HostUrl     = $hostUrl
                            ReferrerUrl = $referrer
                            FileSize    = $_.Length
                            Modified    = $_.LastWriteTime
                        }
                    }
                } catch { }
            }
        } catch {
            Write-Host "WARNING: Zone.Identifier scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\zone_identifiers.csv" -NoTypeInformation
        Write-Host "Zone.Identifier data saved to: $OutputPath\zone_identifiers.csv"
    } else {
        Write-Host "(No Zone.Identifier data found)"
    }
    return $items
}

# Collects recent-file-activity indicators: RecentDocs, TypedPaths,
# RunMRU, and the contents of the Recent Items folder.  Reveals what
# files the suspect opened, what paths they typed, and what they ran.
function Get-RecentFileActivity {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Recent File Activity (MRU / Recent Docs) ==="
    $items = @()

    # Recent Items folder (LNK shortcuts)
    $recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentDir) {
        Get-ChildItem -Path $recentDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $items += [pscustomobject]@{
                Source   = 'RecentItems'
                Name     = $_.Name
                Value    = $_.FullName
                Modified = $_.LastWriteTime
            }
        }
    }

    # Explorer TypedPaths (URLs / paths typed into Explorer address bar)
    $typedPaths = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    if (Test-Path $typedPaths) {
        try {
            $tp = Get-ItemProperty -Path $typedPaths -ErrorAction SilentlyContinue
            $tp.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $items += [pscustomobject]@{
                    Source   = 'TypedPaths'
                    Name     = $_.Name
                    Value    = $_.Value
                    Modified = $null
                }
            }
        } catch { }
    }

    # RunMRU (Start â†’ Run history)
    $runMru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    if (Test-Path $runMru) {
        try {
            $rm = Get-ItemProperty -Path $runMru -ErrorAction SilentlyContinue
            $rm.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'MRUList' } | ForEach-Object {
                $items += [pscustomobject]@{
                    Source   = 'RunMRU'
                    Name     = $_.Name
                    Value    = $_.Value
                    Modified = $null
                }
            }
        } catch { }
    }

    # RecentDocs registry (per extension)
    $recentDocsKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    if (Test-Path $recentDocsKey) {
        try {
            Get-ChildItem -Path $recentDocsKey -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Source   = 'RecentDocs'
                    Name     = $_.PSChildName
                    Value    = "(registry subkey - binary data)"
                    Modified = $null
                }
            }
        } catch { }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\recent_file_activity.csv" -NoTypeInformation
        Write-Host "Recent file activity saved to: $OutputPath\recent_file_activity.csv"
    } else {
        Write-Host "(No recent file activity found)"
    }
    return $items
}

# ============================================================================
# DEVICE & REMOVABLE MEDIA FORENSICS
# ============================================================================

# Enumerates USB storage devices that have been connected, using the
# USBSTOR registry key.  Evidence of USB drives can indicate data
# exfiltration (stealing files from victims).
function Get-USBDeviceHistory {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting USB Device History ==="
    $items = @()

    $usbstorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path $usbstorPath) {
        try {
            Get-ChildItem -Path $usbstorPath -ErrorAction SilentlyContinue | ForEach-Object {
                $deviceClass = $_
                Get-ChildItem -Path $deviceClass.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $serial = $_.PSChildName
                    $props  = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    $items += [pscustomobject]@{
                        DeviceClass  = $deviceClass.PSChildName
                        SerialNumber = $serial
                        FriendlyName = $props.FriendlyName
                        Manufacturer = $props.Mfg
                        Driver       = $props.Driver
                        LastSeen     = $props.LastArrivalDate
                    }
                }
            }
        } catch {
            Write-Host "WARNING: USBSTOR read failed - $_"
        }
    } else {
        Write-Host "(USBSTOR registry key not found)"
    }

    # Also capture currently mounted removable drives
    try {
        Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue | ForEach-Object {
            $items += [pscustomobject]@{
                DeviceClass  = 'MountedRemovable'
                SerialNumber = $_.VolumeSerialNumber
                FriendlyName = "$($_.DeviceID) $($_.VolumeName)"
                Manufacturer = $null
                Driver       = $null
                LastSeen     = "(currently mounted)"
            }
        }
    } catch { }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\usb_device_history.csv" -NoTypeInformation
        Write-Host "USB device history saved to: $OutputPath\usb_device_history.csv"
    } else {
        Write-Host "(No USB device history found)"
    }
    return $items
}

# ============================================================================
# DELETED / RECYCLED DATA
# ============================================================================

# Lists items currently in the Recycle Bin. Suspects often delete
# incriminating files; the Recycle Bin may still contain them.
function Get-RecycleBinContents {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Recycle Bin Contents ==="
    $items = @()

    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.NameSpace(0x0A)  # 0x0A = Recycle Bin

        if ($recycleBin) {
            $recycleBin.Items() | ForEach-Object {
                $items += [pscustomobject]@{
                    Name         = $_.Name
                    OriginalPath = $_.Path
                    Size         = $_.Size
                    Type         = $_.Type
                    DateDeleted  = $recycleBin.GetDetailsOf($_, 2)
                }
            }
        }
    } catch {
        Write-Host "WARNING: Recycle Bin enumeration failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\recycle_bin.csv" -NoTypeInformation
        Write-Host "Recycle Bin metadata saved to: $OutputPath\recycle_bin.csv"
    } else {
        Write-Host "(Recycle Bin is empty or inaccessible)"
    }

    # Copy the actual deleted files ($R* files) from all user Recycle Bins.
    # Each deleted file is stored as $R<id>.<ext> (the content) alongside
    # $I<id>.<ext> (the metadata: original path, deletion time).
    $rbDir = Join-Path $OutputPath "recycle_bin_files"
    New-Item -ItemType Directory -Path $rbDir -Force | Out-Null
    $copied = 0
    $totalSize = 0

    try {
        # All users' recycle bins live under C:\`$Recycle.Bin\<SID>\
        $recyclePaths = Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force -ErrorAction SilentlyContinue
        foreach ($sidDir in $recyclePaths) {
            $sidName = $sidDir.Name
            $destSidDir = Join-Path $rbDir $sidName

            $rbFiles = Get-ChildItem $sidDir.FullName -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\$[RI]' }

            if ($rbFiles) {
                New-Item -ItemType Directory -Path $destSidDir -Force | Out-Null
                foreach ($f in $rbFiles) {
                    try {
                        Copy-Item $f.FullName (Join-Path $destSidDir $f.Name) -Force -ErrorAction Stop
                        $copied++
                        $totalSize += $f.Length
                    } catch {
                        # Some may be locked or permission-denied
                        try {
                            & esentutl.exe /y $f.FullName /d (Join-Path $destSidDir $f.Name) 2>$null
                            if ($LASTEXITCODE -eq 0) { $copied++; $totalSize += $f.Length }
                        } catch { }
                    }
                }
            }
        }
    } catch {
        Write-Host "WARNING: Recycle Bin file copy failed - $_"
    }

    if ($copied -gt 0) {
        $sizeMB = [math]::Round($totalSize / 1MB, 1)
        Write-Host "  Copied $copied recycle bin files ($sizeMB MB) -> $rbDir"
        Write-Host "  \$I files = metadata (original path + delete time)"
        Write-Host "  \$R files = actual deleted file content"
    } else {
        Write-Host "  (No recycle bin files to copy)"
    }

    return $items
}

# ============================================================================
# VOLATILE EVIDENCE (TIME-SENSITIVE)
# ============================================================================

# Captures the DNS client cache, showing recently resolved domains.
# Extremely volatile - lost on reboot.  May reveal C2 servers, cloud
# storage, email providers, or other services the suspect contacted.
function Get-DNSCache {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting DNS Cache ==="
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue |
            Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data
        if ($dns) {
            $dns | Export-Csv "$OutputPath\dns_cache.csv" -NoTypeInformation
            Write-Host "DNS cache saved to: $OutputPath\dns_cache.csv"
        } else {
            Write-Host "(DNS cache is empty)"
        }
        return $dns
    } catch {
        Write-Host "WARNING: DNS cache collection failed - $_"
        return $null
    }
}

# Captures current clipboard text content.  The clipboard might hold
# passwords, bitcoin addresses, or snippets of extortion messages.
# Extremely volatile.
function Get-ClipboardContents {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Capturing Clipboard Contents ==="
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $clip = [System.Windows.Forms.Clipboard]::GetText()
        if ($clip) {
            $clip | Out-File "$OutputPath\clipboard.txt" -Encoding UTF8
            Write-Host "Clipboard contents saved to: $OutputPath\clipboard.txt"
        } else {
            Write-Host "(Clipboard is empty or contains non-text data)"
        }
        return $clip
    } catch {
        Write-Host "WARNING: Clipboard capture failed - $_"
        return $null
    }
}

# Captures mapped network drives and active SMB shares.  May reveal
# connections to other machines (the second VM) or exfiltration targets.
function Get-MappedDrivesAndShares {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Mapped Drives & Network Shares ==="
    $items = @()

    # Mapped drives (net use)
    try {
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayRoot } | ForEach-Object {
                $items += [pscustomobject]@{
                    Type       = 'MappedDrive'
                    Name       = $_.Name
                    Root       = $_.DisplayRoot
                    UsedGB     = [math]::Round(($_.Used / 1GB), 2)
                    FreeGB     = [math]::Round(($_.Free / 1GB), 2)
                }
            }
    } catch { }

    # SMB shares hosted on this machine
    try {
        Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
            $items += [pscustomobject]@{
                Type       = 'SMBShare'
                Name       = $_.Name
                Root       = $_.Path
                UsedGB     = $null
                FreeGB     = $null
            }
        }
    } catch { }

    # Active SMB sessions (who is connected TO us)
    try {
        Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object {
            $items += [pscustomobject]@{
                Type       = 'ActiveSMBSession'
                Name       = $_.ClientUserName
                Root       = $_.ClientComputerName
                UsedGB     = $null
                FreeGB     = $null
            }
        }
    } catch { }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\mapped_drives_shares.csv" -NoTypeInformation
        Write-Host "Mapped drives/shares saved to: $OutputPath\mapped_drives_shares.csv"
    } else {
        Write-Host "(No mapped drives or shares found)"
    }
    return $items
}

# ============================================================================
# COMMAND HISTORY & USER ACTIONS
# ============================================================================

# Retrieves PowerShell console history files for all users.
# Shows what commands the suspect executed, which could reveal
# reconnaissance, data collection, or scripting of extortion tools.
function Get-PowerShellHistory {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting PowerShell Command History ==="
    $items = @()

    # PSReadLine history for each user profile
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($prof in $profiles) {
        $histPath = Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $histPath) {
            try {
                $lines = Get-Content -Path $histPath -ErrorAction SilentlyContinue
                $lineNum = 0
                foreach ($line in $lines) {
                    $lineNum++
                    $items += [pscustomobject]@{
                        User    = $prof.Name
                        LineNum = $lineNum
                        Command = $line
                        Source  = 'PSReadLine'
                    }
                }
                # Also copy the raw file for evidence
                $destFile = Join-Path $OutputPath "ps_history_$($prof.Name).txt"
                Copy-Item -Path $histPath -Destination $destFile -ErrorAction SilentlyContinue
            } catch {
                Write-Host "WARNING: Could not read PS history for $($prof.Name) - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\powershell_history.csv" -NoTypeInformation
        Write-Host "PowerShell history saved to: $OutputPath\powershell_history.csv"
    } else {
        Write-Host "(No PowerShell history files found)"
    }
    return $items
}

# ============================================================================
# REMOTE ACCESS / INTER-VM LINKING
# ============================================================================

# Collects RDP-related artefacts: recent RDP connections from registry,
# active logon sessions, and RDP cache files.  Critical for proving
# the suspect connected the two VMs together.
function Get-RDPAndRemoteSessions {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting RDP & Remote Session Artifacts ==="
    $items = @()

    # Recent RDP connections (Terminal Server Client)
    $rdpServersKey = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
    if (Test-Path $rdpServersKey) {
        try {
            Get-ChildItem -Path $rdpServersKey -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $items += [pscustomobject]@{
                    Type     = 'RDP_RecentServer'
                    Target   = $_.PSChildName
                    Username = $props.UsernameHint
                    Detail   = $null
                }
            }
        } catch { }
    }

    # Default RDP connection settings
    $rdpDefault = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    if (Test-Path $rdpDefault) {
        try {
            $def = Get-ItemProperty -Path $rdpDefault -ErrorAction SilentlyContinue
            $def.PSObject.Properties | Where-Object { $_.Name -like 'MRU*' } | ForEach-Object {
                $items += [pscustomobject]@{
                    Type     = 'RDP_MRU'
                    Target   = $_.Value
                    Username = $null
                    Detail   = $_.Name
                }
            }
        } catch { }
    }

    # Active logon sessions (qwinsta/query user)
    try {
        $sessions = qwinsta 2>$null
        if ($sessions) {
            foreach ($line in $sessions) {
                if ($line -match '^\s*([\w>]+)\s+(\S+)?\s+(\d+)\s+(\S+)') {
                    $items += [pscustomobject]@{
                        Type     = 'ActiveSession'
                        Target   = $Matches[1]
                        Username = $Matches[2]
                        Detail   = "SessionId=$($Matches[3]) State=$($Matches[4])"
                    }
                }
            }
        }
    } catch { }

    # RDP bitmap cache files (evidence of remote desktop activity)
    $rdpCacheDirs = @(
        "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache"
    )
    foreach ($dir in $rdpCacheDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Type     = 'RDP_CacheFile'
                    Target   = $_.Name
                    Username = $null
                    Detail   = "$([math]::Round($_.Length / 1KB, 2)) KB - Modified: $($_.LastWriteTime)"
                }
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\rdp_remote_sessions.csv" -NoTypeInformation
        Write-Host "RDP/remote session data saved to: $OutputPath\rdp_remote_sessions.csv"
    } else {
        Write-Host "(No RDP or remote session artifacts found)"
    }
    return $items
}

# ============================================================================
# MEMORY ANALYSIS (POST-ACQUISITION)
# ============================================================================

# Performs automated memory analysis on a RAM dump using:
#   1. Volatility 3 (if vol.py or vol.exe is available) — runs pslist, netscan,
#      filescan, cmdline, malfind plugins and saves CSV/text output
#   2. SysInternals strings.exe (if available) — extracts IPs, emails, URLs,
#      bitcoin addresses, file paths, and passwords from the raw dump
#   3. Falls back to writing an advisory note if neither tool is present
#
# Returns an array of IOC objects (for the HTML report) or $null.
function Get-MemoryStrings {
    param(
        [string]$OutputPath,
        [string]$RamDumpPath,
        [string]$ScriptRoot = $PSScriptRoot
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Memory Dump Analysis ==="

    if (-not $RamDumpPath -or -not (Test-Path $RamDumpPath)) {
        Write-Host "(No RAM dump available — skipping memory analysis)"
        return $null
    }

    $dumpItem = Get-Item $RamDumpPath
    $sizeMB   = [math]::Round($dumpItem.Length / 1MB, 2)
    Write-Host "RAM dump: $($dumpItem.Name) ($sizeMB MB)"

    $memDir = Join-Path $OutputPath "memory_analysis"
    New-Item -ItemType Directory -Path $memDir -Force | Out-Null

    $iocs = @()   # collected IOC items for the HTML report

    # ── 1. VOLATILITY 3 AUTO-ANALYSIS ────────────────────────────────────────
    $volPaths = @(
        (Get-Command vol -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Get-Command vol.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Get-Command vol.py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Join-Path $ScriptRoot "bin\volatility3\vol.exe"),
        (Join-Path $ScriptRoot "bin\volatility3\vol.py"),
        (Join-Path $ScriptRoot "bin\vol.exe"),
        (Join-Path $ScriptRoot "bin\vol.py")
    ) | Where-Object { $_ -and (Test-Path $_) }

    # Also search for vol.py inside any volatility3-* source tree in bin\
    if (-not $volPaths) {
        $volPySearch = Get-ChildItem -Path (Join-Path $ScriptRoot "bin") -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($volPySearch) { $volPaths = @($volPySearch.FullName) }
    }

    $vol = $volPaths | Select-Object -First 1

    # Check if Python + vol.py is viable
    $python = $null
    if (-not $vol) {
        $python = (Get-Command python -ErrorAction SilentlyContinue).Path
        if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue).Path }
        if ($python) {
            # Check if volatility3 is installed as a Python package
            try {
                $volCheck = & $python -c "import volatility3; print(volatility3.__file__)" 2>$null
                if ($volCheck) {
                    $vol = "python_module"
                    Write-Host "  Volatility 3 found as Python module"
                }
            } catch { }
        }
    }

    # If vol is a .py file, we need Python to run it
    if ($vol -and $vol -ne "python_module" -and $vol -like "*.py") {
        $python = (Get-Command python -ErrorAction SilentlyContinue).Path
        if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue).Path }
        if ($python) {
            $vol = "python_script:$vol"
            Write-Host "  Volatility 3 source found — will run via Python"
        } else {
            Write-Host "  WARNING: vol.py found but Python not available in PATH"
            $vol = $null
        }
    }

    if ($vol) {
        Write-Host "  Running Volatility 3 analysis (this may take several minutes)..."
        Write-Host "  Using: $vol"

        # Plugins to run — each maps to inter-VM linking or suspect profiling
        $plugins = @(
            @{ Name = 'windows.pslist';    Desc = 'Running processes' },
            @{ Name = 'windows.netscan';   Desc = 'Network connections (inter-VM links)' },
            @{ Name = 'windows.filescan';  Desc = 'Open file handles' },
            @{ Name = 'windows.cmdline';   Desc = 'Process command lines' },
            @{ Name = 'windows.malfind';   Desc = 'Injected/suspicious code regions' },
            @{ Name = 'windows.registry.hivelist'; Desc = 'Registry hives in memory' }
        )

        foreach ($plugin in $plugins) {
            $outFile = Join-Path $memDir "$($plugin.Name -replace '\.','_').txt"
            Write-Host "  [$($plugin.Name)] $($plugin.Desc)..."
            try {
                if ($vol -eq "python_module") {
                    & $python -m volatility3 -f $RamDumpPath $plugin.Name 2>$null | Out-File $outFile -Encoding UTF8
                } elseif ($vol -like "python_script:*") {
                    $volScript = $vol -replace '^python_script:',''
                    $volDir = Split-Path $volScript -Parent
                    $env:PYTHONPATH = $volDir
                    & $python $volScript -f $RamDumpPath $plugin.Name 2>$null | Out-File $outFile -Encoding UTF8
                } else {
                    & $vol -f $RamDumpPath $plugin.Name 2>$null | Out-File $outFile -Encoding UTF8
                }
                if (Test-Path $outFile) {
                    $lineCount = (Get-Content $outFile -ErrorAction SilentlyContinue | Measure-Object).Count
                    Write-Host "    -> $lineCount lines saved to $outFile"
                    if ($lineCount -gt 2) {
                        $iocs += [pscustomobject]@{
                            Source  = 'Volatility3'
                            Plugin  = $plugin.Name
                            Detail  = "$($plugin.Desc) — $lineCount entries"
                            File    = $outFile
                        }
                    }
                }
            } catch {
                Write-Host "    WARNING: $($plugin.Name) failed - $_"
            }
        }
        Write-Host "  Volatility analysis complete -> $memDir"
    } else {
        Write-Host "  Volatility 3 not found (checked PATH and bin\ folder)"
        Write-Host "  To enable auto-analysis, install Volatility 3:"
        Write-Host "    pip install volatility3"
        Write-Host "    Or download vol.exe from: https://github.com/volatilityfoundation/volatility3"
        Write-Host "    Place in: $ScriptRoot\bin\"
    }

    # ── 2. STRINGS EXTRACTION ────────────────────────────────────────────────
    $stringsPaths = @(
        (Get-Command strings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Get-Command strings.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Get-Command strings64.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue),
        (Join-Path $ScriptRoot "bin\strings64.exe"),
        (Join-Path $ScriptRoot "bin\strings.exe"),
        (Join-Path $ScriptRoot "bin\Strings\strings64.exe"),
        (Join-Path $ScriptRoot "bin\Strings\strings.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }

    $strings = $stringsPaths | Select-Object -First 1

    if ($strings) {
        Write-Host ""
        Write-Host "  Running strings extraction on RAM dump..."
        Write-Host "  Using: $strings"

        # Accept EULA silently for SysInternals strings
        $stringsArgs = @('-n', '8', '-nobanner', '-accepteula', $RamDumpPath)

        # Define forensic patterns to search for
        $patterns = @(
            @{ Name = 'emails';     Regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}';  Desc = 'Email addresses' },
            @{ Name = 'ipv4';       Regex = '\b(?:\d{1,3}\.){3}\d{1,3}\b';                      Desc = 'IPv4 addresses' },
            @{ Name = 'urls';       Regex = 'https?://[^\s"''<>]+';                              Desc = 'HTTP/HTTPS URLs' },
            @{ Name = 'bitcoin';    Regex = '\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b';             Desc = 'Bitcoin addresses' },
            @{ Name = 'passwords';  Regex = '(?i)password[\s:=]+\S+';                           Desc = 'Password references' },
            @{ Name = 'unc_paths';  Regex = '\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9$._-]+';          Desc = 'UNC network paths (inter-VM links)' }
        )

        try {
            # Run strings once and save full output to temp file for grep
            $rawStringsFile = Join-Path $memDir "strings_raw.txt"
            Write-Host "  Extracting strings (min length 8)... this may take a few minutes"
            & $strings $stringsArgs 2>$null | Out-File $rawStringsFile -Encoding UTF8

            if (Test-Path $rawStringsFile) {
                $rawSize = [math]::Round((Get-Item $rawStringsFile).Length / 1MB, 1)
                Write-Host "  Raw strings: $rawSize MB -> $rawStringsFile"

                # Now grep each pattern from the raw strings
                foreach ($pat in $patterns) {
                    $destFile = Join-Path $memDir "strings_$($pat.Name).txt"
                    Write-Host "  Searching for $($pat.Desc)..."
                    try {
                        $matches = Select-String -Path $rawStringsFile -Pattern $pat.Regex -AllMatches -ErrorAction SilentlyContinue
                        if ($matches) {
                            # Deduplicate and save
                            $unique = $matches | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
                            $unique | Out-File $destFile -Encoding UTF8
                            $count = $unique.Count
                            Write-Host "    -> $count unique $($pat.Desc) saved to $destFile"

                            if ($count -gt 0) {
                                # Add top hits to IOC list for HTML report
                                $preview = ($unique | Select-Object -First 10) -join '; '
                                $iocs += [pscustomobject]@{
                                    Source  = 'StringsExtraction'
                                    Plugin  = $pat.Name
                                    Detail  = "$count unique $($pat.Desc) — top: $preview"
                                    File    = $destFile
                                }
                            }
                        } else {
                            Write-Host "    (none found)"
                        }
                    } catch {
                        Write-Host "    WARNING: Pattern search failed for $($pat.Name) - $_"
                    }
                }
            }
        } catch {
            Write-Host "  ERROR during strings extraction: $_"
        }

        Write-Host "  Strings extraction complete -> $memDir"
    } else {
        Write-Host ""
        Write-Host "  strings.exe not found (checked PATH and bin\ folder)"
        Write-Host "  To enable strings extraction:"
        Write-Host "    Download: https://learn.microsoft.com/en-us/sysinternals/downloads/strings"
        Write-Host "    Place strings64.exe in: $ScriptRoot\bin\"
    }

    # ── 3. SUMMARY NOTE ─────────────────────────────────────────────────────
    $toolsFound = @()
    if ($vol) { $toolsFound += "Volatility 3" }
    if ($strings) { $toolsFound += "strings.exe" }
    $toolStatus = if ($toolsFound.Count -gt 0) { $toolsFound -join ' + ' } else { "NONE — manual analysis required" }

    $note = @"
MEMORY DUMP ANALYSIS SUMMARY
==============================
File    : $($dumpItem.Name)
Size    : $sizeMB MB
Path    : $($dumpItem.FullName)
Hash    : (see hashes.csv)
Tools   : $toolStatus
Results : $memDir

$(if ($iocs.Count -gt 0) {
    "IOCs FOUND:"
    foreach ($i in $iocs) { "  [$($i.Source)] $($i.Plugin): $($i.Detail)" }
} else {
    "No automated IOCs extracted. Manual analysis recommended."
})

MANUAL ANALYSIS COMMANDS:
  Volatility 3:
    vol.py -f "$RamDumpPath" windows.pslist
    vol.py -f "$RamDumpPath" windows.netscan
    vol.py -f "$RamDumpPath" windows.filescan
    vol.py -f "$RamDumpPath" windows.cmdline
    vol.py -f "$RamDumpPath" windows.malfind

  SysInternals strings:
    strings.exe -n 8 "$RamDumpPath" | findstr /i "@" > emails.txt
    strings.exe -n 8 "$RamDumpPath" | findstr /i "http" > urls.txt
    strings.exe -n 8 "$RamDumpPath" | findstr /i "\\\\" > unc_paths.txt
"@

    $note | Out-File "$memDir\memory_analysis_summary.txt" -Encoding UTF8
    Write-Host ""
    Write-Host "  Summary saved to: $memDir\memory_analysis_summary.txt"

    if ($iocs.Count -gt 0) {
        Write-Host "  $($iocs.Count) IOC categories found — see HTML report for details"
        return $iocs
    }

    return $null
}

# ============================================================================
# BROWSER ARTIFACTS & DOWNLOADS
# ============================================================================

# Copies browser SQLite artifacts (History/Bookmarks) and enumerates the user's Downloads folder.
# Returns a PSCustomObject with `Downloads` and `BrowserCopies` fields describing copied artifacts.
function Get-BrowserArtifactsAndDownloads {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Browser Artifacts & Downloads (best effort) ==="
    $browserOut = Join-Path $OutputPath "browser_artifacts"
    New-Item -ItemType Directory -Path $browserOut -Force | Out-Null

    $downloadsFolder = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
    $downloads = $null
    if (Test-Path $downloadsFolder) {
        try {
            $downloads = Get-ChildItem -Path $downloadsFolder -File -ErrorAction SilentlyContinue | Select-Object Name, FullName, Length, LastWriteTime
            if ($downloads) {
                $downloads | Export-Csv "$OutputPath\downloads.csv" -NoTypeInformation
                Write-Host "Downloads listing saved to: $OutputPath\downloads.csv"
            }
        } catch {
            Write-Host "WARNING: Failed to enumerate Downloads - $_"
        }
    } else {
        Write-Host "(Downloads folder not found)"
    }

    $copies = @()
    $targets = @(
        @{ Name='Chrome-History'; Path=Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\History' },
        @{ Name='Edge-History'; Path=Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\History' }
    )

    foreach ($t in $targets) {
        $source = $t.Path
        if (Test-Path $source) {
            $dest = Join-Path $browserOut ($t.Name + '.sqlite')
            try {
                Copy-Item -Path $source -Destination $dest -ErrorAction Stop
                $copies += [pscustomobject]@{ Artifact=$t.Name; Path=$dest; Status='Copied' }
            } catch {
                $copies += [pscustomobject]@{ Artifact=$t.Name; Path=$source; Status="Copy failed: $_" }
            }
        } else {
            $copies += [pscustomobject]@{ Artifact=$t.Name; Path=$source; Status='Not found' }
        }
    }

    return [pscustomobject]@{
        Downloads = $downloads
        BrowserCopies = $copies
    }
}

# ============================================================================
# DEEPER ANTI-FORENSICS & CONCEALMENT DETECTION
# ============================================================================

# Enumerates Volume Shadow Copies (VSS snapshots).  These contain
# previous versions of files and can be used to recover deleted evidence.
# If shadow copies are suspiciously absent, the suspect may have deleted
# them to cover tracks (vssadmin delete shadows /all /quiet).
function Get-ShadowCopies {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Enumerating Volume Shadow Copies ==="
    $items = @()

    try {
        $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
        foreach ($s in $shadows) {
            $items += [pscustomobject]@{
                ShadowID       = $s.ID
                VolumeName     = $s.VolumeName
                InstallDate    = $s.InstallDate
                OriginMachine  = $s.OriginatingMachine
                ServiceMachine = $s.ServiceMachine
            }
        }
    } catch {
        Write-Host "WARNING: Shadow copy enumeration failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\shadow_copies.csv" -NoTypeInformation
        Write-Host "Shadow copies saved to: $OutputPath\shadow_copies.csv"
    } else {
        Write-Host "(No shadow copies found - may indicate VSS deletion)"
    }
    return $items
}

# Detects potential timestamp manipulation (timestomping).
# Under normal Windows operation, a file's CreationTime is always
# <= its LastWriteTime.  If Created > Modified, the timestamps
# have been tampered with — a classic anti-forensic technique used
# to make malicious files blend in by appearing older.
function Get-TimestompDetection {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Detecting Timestomped Files ==="
    $items = @()

    $scanPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\AppData\Roaming",
        "C:\Temp",
        "C:\Users\Public"
    )

    foreach ($dir in $scanPaths) {
        if (-not (Test-Path $dir)) { continue }
        try {
            Get-ChildItem -Path $dir -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                # Created should be <= Modified; if Created > Modified by more than 24 hours,
                # timestamps were likely manipulated. Small deltas (< 24h) are common from
                # file copies, Windows Updates, and app installers — not forensically significant.
                if ($_.CreationTime -gt $_.LastWriteTime) {
                    $delta = ($_.CreationTime - $_.LastWriteTime).TotalHours
                    if ($delta -ge 24) {
                        $items += [pscustomobject]@{
                            FilePath   = $_.FullName
                            Name       = $_.Name
                            Created    = $_.CreationTime
                            Modified   = $_.LastWriteTime
                            DeltaHours = [math]::Round($delta, 2)
                            SizeKB     = [math]::Round(($_.Length / 1KB), 2)
                        }
                    }
                }
            }
        } catch {
            Write-Host "WARNING: Timestomp scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\timestomped_files.csv" -NoTypeInformation
        Write-Host "Timestomped files saved to: $OutputPath\timestomped_files.csv"
    } else {
        Write-Host "(No timestamp anomalies detected)"
    }
    return $items
}

# Reads the UserAssist registry keys that track GUI program launches.
# Programme names are ROT13-encoded.  This reveals what executables
# the suspect ran, how many times, and when they last ran them.
function Get-UserAssistHistory {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting UserAssist Program Execution History ==="
    $items = @()

    # ROT13 decode helper
    function ConvertFrom-ROT13 {
        param([string]$Text)
        $chars = $Text.ToCharArray()
        $decoded = -join ($chars | ForEach-Object {
            $c = $_
            if ($c -ge [char]'A' -and $c -le [char]'Z') {
                [char]((([int]$c - 65 + 13) % 26) + 65)
            } elseif ($c -ge [char]'a' -and $c -le [char]'z') {
                [char]((([int]$c - 97 + 13) % 26) + 97)
            } else {
                $c
            }
        })
        return $decoded
    }

    # UserAssist GUID folders (CEBFF5CD = executables, F4E57C4B = shortcuts)
    $uaKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count'
    )

    foreach ($keyPath in $uaKeys) {
        if (-not (Test-Path $keyPath)) { continue }
        try {
            $source = if ($keyPath -match 'CEBFF5CD') { 'Executables' } else { 'Shortcuts' }
            $key = Get-Item -Path $keyPath -ErrorAction SilentlyContinue
            foreach ($valName in $key.GetValueNames()) {
                if (-not $valName) { continue }
                $decoded = ConvertFrom-ROT13 -Text $valName
                $data = $key.GetValue($valName)
                $runCount = 0
                $lastRun  = $null
                $focusTime = 0

                # Parse the binary value (UserAssist v5 structure - Win7+)
                if ($data -and $data.Length -ge 72) {
                    $runCount  = [BitConverter]::ToUInt32($data, 4)
                    $focusTime = [BitConverter]::ToInt32($data, 12)
                    $ft = [BitConverter]::ToInt64($data, 60)
                    if ($ft -gt 0) {
                        try { $lastRun = [DateTime]::FromFileTime($ft) } catch { }
                    }
                }

                if ($runCount -gt 0 -or $lastRun) {
                    $items += [pscustomobject]@{
                        ProgramName = $decoded
                        RunCount    = $runCount
                        LastRun     = $lastRun
                        FocusTime   = $focusTime
                        Source      = $source
                    }
                }
            }
        } catch {
            Write-Host "WARNING: UserAssist read failed on $keyPath - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\userassist.csv" -NoTypeInformation
        Write-Host "UserAssist data saved to: $OutputPath\userassist.csv"
    } else {
        Write-Host "(No UserAssist data found)"
    }
    return $items
}

# Checks the Windows hosts file for non-default entries.
# Attackers modify the hosts file to redirect domains (e.g. block
# antivirus updates, redirect banking sites, or create covert channels).
function Get-HostsFileCheck {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Checking Hosts File for Tampering ==="
    $items = @()

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        try {
            $hostsInfo = Get-Item $hostsPath -ErrorAction SilentlyContinue
            $lines = Get-Content $hostsPath -ErrorAction SilentlyContinue

            # Record file metadata
            $items += [pscustomobject]@{
                IP       = '(metadata)'
                Hostname = $hostsPath
                Status   = "Modified: $($hostsInfo.LastWriteTime) | Size: $($hostsInfo.Length) bytes"
            }

            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                # Skip empty lines and comments
                if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
                # Parse IP hostname entries
                if ($trimmed -match '^(\S+)\s+(.+)$') {
                    $ip   = $Matches[1]
                    $host_ = $Matches[2].Trim()

                    # Default entries are 127.0.0.1 localhost and ::1 localhost
                    $isDefault = ($ip -eq '127.0.0.1' -and $host_ -eq 'localhost') -or
                                 ($ip -eq '::1' -and $host_ -eq 'localhost')

                    $status = if ($isDefault) { 'Default' } else { 'SUSPICIOUS - Non-default entry' }

                    $items += [pscustomobject]@{
                        IP       = $ip
                        Hostname = $host_
                        Status   = $status
                    }
                }
            }
        } catch {
            Write-Host "WARNING: Hosts file read failed - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\hosts_file.csv" -NoTypeInformation
        Write-Host "Hosts file analysis saved to: $OutputPath\hosts_file.csv"
    } else {
        Write-Host "(Hosts file not found or empty)"
    }
    return $items
}

# Enumerates Windows Firewall rules, focusing on rules that ALLOW
# inbound connections.  Attackers may add firewall rules to permit
# reverse shells, C2 listeners, or data exfiltration channels.
function Get-FirewallRules {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Suspicious Firewall Rules ==="
    $items = @()

    try {
        # Focus on inbound Allow rules and any rules created for non-system programs
        $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
        foreach ($r in $rules) {
            try {
                $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addrFilter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $items += [pscustomobject]@{
                    DisplayName   = $r.DisplayName
                    Direction     = $r.Direction.ToString()
                    Action        = $r.Action.ToString()
                    Protocol      = $portFilter.Protocol
                    LocalPort     = $portFilter.LocalPort
                    RemoteAddress = $addrFilter.RemoteAddress
                    Enabled       = $r.Enabled.ToString()
                    Profile       = $r.Profile.ToString()
                }
            } catch { }
        }
    } catch {
        Write-Host "WARNING: Firewall rule collection failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\firewall_rules.csv" -NoTypeInformation
        Write-Host "Firewall rules saved to: $OutputPath\firewall_rules.csv"
    } else {
        Write-Host "(No matching firewall rules found)"
    }
    return $items
}

# Checks Windows Defender exclusion settings.  Attackers frequently
# add exclusions for paths, processes, or file extensions to prevent
# their malware from being detected by real-time protection.
function Get-DefenderExclusions {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Checking Windows Defender Exclusions ==="
    $items = @()

    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue

        if ($prefs.ExclusionPath) {
            foreach ($p in $prefs.ExclusionPath) {
                $items += [pscustomobject]@{
                    Type  = 'PathExclusion'
                    Value = $p
                    Risk  = 'Malware can hide in excluded directories'
                }
            }
        }

        if ($prefs.ExclusionProcess) {
            foreach ($p in $prefs.ExclusionProcess) {
                $items += [pscustomobject]@{
                    Type  = 'ProcessExclusion'
                    Value = $p
                    Risk  = 'Excluded process will not be scanned'
                }
            }
        }

        if ($prefs.ExclusionExtension) {
            foreach ($e in $prefs.ExclusionExtension) {
                $items += [pscustomobject]@{
                    Type  = 'ExtensionExclusion'
                    Value = $e
                    Risk  = 'Files with this extension bypass scanning'
                }
            }
        }

        if ($prefs.ExclusionIpAddress) {
            foreach ($ip in $prefs.ExclusionIpAddress) {
                $items += [pscustomobject]@{
                    Type  = 'IPExclusion'
                    Value = $ip
                    Risk  = 'Network traffic to/from this IP bypasses scanning'
                }
            }
        }
    } catch {
        Write-Host "WARNING: Defender preference check failed (may need admin) - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\defender_exclusions.csv" -NoTypeInformation
        Write-Host "Defender exclusions saved to: $OutputPath\defender_exclusions.csv"
    } else {
        Write-Host "(No Defender exclusions configured)"
    }
    return $items
}
# ============================================================================
# DEEP-DIVE COLLECTORS
# ============================================================================

# Collects all saved WiFi network profiles.  Each stored profile
# reveals a network the device has connected to, which can place
# the suspect at specific locations or reveal personal hotspot
# usage.  Includes authentication type and auto-connect status.
function Get-WiFiProfiles {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Saved WiFi Profiles ==="
    $items = @()

    try {
        $profiles = netsh wlan show profiles 2>$null
        $profileMatches = $profiles | Select-String 'All User Profile\s+:\s+(.+)$'
        $profileNames = @()
        if ($profileMatches) {
            $profileNames = $profileMatches | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        }

        foreach ($name in $profileNames) {
            $detail = netsh wlan show profile name="$name" 2>$null
            $authMatch = $detail | Select-String 'Authentication\s+:\s+(.+)$' | Select-Object -First 1
            $encMatch  = $detail | Select-String 'Cipher\s+:\s+(.+)$' | Select-Object -First 1
            $connMatch = $detail | Select-String 'Connection mode\s+:\s+(.+)$' | Select-Object -First 1
            
            $auth = if ($authMatch) { $authMatch.Matches.Groups[1].Value.Trim() } else { 'N/A' }
            $enc  = if ($encMatch)  { $encMatch.Matches.Groups[1].Value.Trim() }  else { 'N/A' }
            $connMode = if ($connMatch) { $connMatch.Matches.Groups[1].Value.Trim() } else { 'N/A' }
            $autoConnect = if ($connMode -match 'auto') { 'Yes' } else { 'No' }

            $items += [pscustomobject]@{
                ProfileName    = $name
                Authentication = $auth
                Encryption     = $enc
                ConnectionMode = $connMode
                AutoConnect    = $autoConnect
            }
        }
    } catch {
        Write-Host "WARNING: WiFi profile collection failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\wifi_profiles.csv" -NoTypeInformation
        Write-Host "WiFi profiles saved: $($items.Count) networks to $OutputPath\wifi_profiles.csv"
    } else {
        Write-Host "(No saved WiFi profiles found)"
    }
    return $items
}

# Collects the current desktop wallpaper path and any cached theme
# images.  Wallpaper can reveal personal interests, inappropriate
# imagery, or organisational affiliation.
function Get-WallpaperInfo {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Desktop Wallpaper Info ==="
    $items = @()

    try {
        # Current wallpaper from registry
        $wp = Get-ItemPropertyValue "HKCU:\Control Panel\Desktop" -Name Wallpaper -ErrorAction SilentlyContinue
        if ($wp) {
            $wpItem = Get-Item $wp -ErrorAction SilentlyContinue
            $items += [pscustomobject]@{
                Source   = 'CurrentWallpaper'
                Path     = $wp
                SizeKB   = if ($wpItem) { [math]::Round($wpItem.Length / 1KB, 1) } else { 'N/A' }
                Modified = if ($wpItem) { $wpItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            }
        }

        # Cached theme images
        $themeCache = "$env:APPDATA\Microsoft\Windows\Themes\CachedFiles"
        if (Test-Path $themeCache) {
            Get-ChildItem $themeCache -File -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Source   = 'CachedTheme'
                    Path     = $_.FullName
                    SizeKB   = [math]::Round($_.Length / 1KB, 1)
                    Modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }

        # Lockscreen cache
        $lockscreen = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\Assets"
        if (Test-Path $lockscreen) {
            $lockItems = Get-ChildItem $lockscreen -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100KB } | Sort-Object LastWriteTime -Descending | Select-Object -First 5
            foreach ($f in $lockItems) {
                $items += [pscustomobject]@{
                    Source   = 'LockscreenAsset'
                    Path     = $f.FullName
                    SizeKB   = [math]::Round($f.Length / 1KB, 1)
                    Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
    } catch {
        Write-Host "WARNING: Wallpaper collection failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\wallpaper_info.csv" -NoTypeInformation
        Write-Host "Wallpaper info saved to: $OutputPath\wallpaper_info.csv"
    } else {
        Write-Host "(No wallpaper information found)"
    }
    return $items
}

# Extracts saved bookmarks from Chrome and Edge browsers by parsing
# their JSON bookmark files.  Bookmarks indicate deliberate, repeated
# interest in specific sites - a stronger signal than browsing history.
function Get-BrowserBookmarks {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Browser Bookmarks ==="
    $items = @()

    $browsers = @{
        'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
        'Edge'   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"
    }

    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            try {
                $json = Get-Content $browser.Value -Raw -Encoding UTF8 | ConvertFrom-Json
                $roots = $json.roots

                # Recursive bookmark walker
                $walkBookmarks = {
                    param($node, $folder, $browserName)
                    if ($node.type -eq 'url') {
                        [pscustomobject]@{
                            Browser = $browserName
                            Folder  = $folder
                            Name    = $node.name
                            URL     = $node.url
                        }
                    }
                    if ($node.children) {
                        foreach ($child in $node.children) {
                            & $walkBookmarks $child "$folder/$($child.name)" $browserName
                        }
                    }
                }

                foreach ($rootName in @('bookmark_bar', 'other', 'synced')) {
                    $rootNode = $roots.$rootName
                    if ($rootNode) {
                        $results = & $walkBookmarks $rootNode $rootName $browser.Key
                        if ($results) { $items += @($results) }
                        if ($rootNode.children) {
                            foreach ($child in $rootNode.children) {
                                $results = & $walkBookmarks $child "$rootName" $browser.Key
                                if ($results) { $items += @($results) }
                            }
                        }
                    }
                }
            } catch {
                Write-Host "WARNING: Failed to parse $($browser.Key) bookmarks - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\browser_bookmarks.csv" -NoTypeInformation
        Write-Host "Browser bookmarks saved: $($items.Count) bookmarks to $OutputPath\browser_bookmarks.csv"
    } else {
        Write-Host "(No browser bookmarks found)"
    }
    return $items
}

# Extracts Google and Bing search queries from browser history SQLite
# databases.  Requires a prior run of Get-BrowserArtifactsAndDownloads
# to copy the SQLite files.  Search queries reveal user intentions
# and investigative behaviour more directly than page titles.
function Get-BrowserSearchHistory {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Extracting Browser Search Queries ==="
    $items = @()

    # Look for copied browser SQLite databases
    $browserDir = "$OutputPath\browser_artifacts"
    $dbFiles = @()
    if (Test-Path $browserDir) {
        $dbFiles = Get-ChildItem $browserDir -Filter "*-History.sqlite" -ErrorAction SilentlyContinue
    }

    if ($dbFiles.Count -eq 0) {
        Write-Host "(No browser SQLite databases found - run Get-BrowserArtifactsAndDownloads first)"
        return $items
    }

    # Try to use Python for SQLite parsing (more reliable than System.Data.SQLite)
    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Path
    if (-not $pythonPath) {
        $pythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Path
    }

    if ($pythonPath) {
        foreach ($db in $dbFiles) {
            $browserName = $db.Name -replace '-History\.sqlite$', ''
            $pyScript = @"
import sqlite3, json, sys
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timedelta

def chrome_time(t):
    try:
        return (datetime(1601,1,1) + timedelta(microseconds=t)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return '?'

conn = sqlite3.connect(r'$($db.FullName)')
cur = conn.cursor()
cur.execute("SELECT url, last_visit_time FROM urls WHERE url LIKE '%google.com/search%' OR url LIKE '%bing.com/search%' ORDER BY last_visit_time DESC")
results = []
seen = set()
for url, lvt in cur.fetchall():
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    query = params.get('q', params.get('Q', ['']))[0]
    if query and query not in seen:
        seen.add(query)
        engine = 'Google' if 'google.com' in url else 'Bing'
        results.append({'ts': chrome_time(lvt), 'engine': engine, 'query': unquote(query)})
conn.close()
print(json.dumps(results))
"@
            try {
                $pyResult = $pyScript | & $pythonPath - 2>$null
                if ($pyResult) {
                    $searches = $pyResult | ConvertFrom-Json
                    foreach ($s in $searches) {
                        $items += [pscustomobject]@{
                            Timestamp = $s.ts
                            Engine    = "$($s.engine) ($browserName)"
                            Query     = $s.query
                        }
                    }
                }
            } catch {
                Write-Host "WARNING: Failed to parse $browserName search history - $_"
            }
        }
    } else {
        Write-Host "WARNING: Python not found - cannot parse SQLite databases for search history"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\browser_search_history.csv" -NoTypeInformation
        Write-Host "Search history saved: $($items.Count) queries to $OutputPath\browser_search_history.csv"
    } else {
        Write-Host "(No browser search queries found)"
    }
    return $items
}

# Extracts Windows Activity History from the ActivitiesCache.db
# SQLite database.  This timeline records every application the
# user interacted with including timestamps, providing a detailed
# usage profile even when browser history is cleared.
function Get-WindowsTimeline {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Windows Activity Timeline ==="
    $items = @()

    # Find the largest (most active) ActivitiesCache.db
    $dbFiles = Get-ChildItem "$env:LOCALAPPDATA\ConnectedDevicesPlatform" -Recurse -Filter "ActivitiesCache.db" -ErrorAction SilentlyContinue | Sort-Object Length -Descending
    
    if ($dbFiles.Count -eq 0) {
        Write-Host "(No Activity History database found)"
        return $items
    }

    $targetDb = $dbFiles[0].FullName
    Write-Host "Using timeline database: $targetDb ($([math]::Round($dbFiles[0].Length / 1MB, 1)) MB)"

    # Copy DB to evidence (it may be locked)
    $copyPath = "$OutputPath\ActivitiesCache.db"
    try {
        Copy-Item $targetDb $copyPath -Force -ErrorAction Stop
    } catch {
        Write-Host "WARNING: Could not copy timeline DB (may be locked) - reading directly"
        $copyPath = $targetDb
    }

    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Path
    if (-not $pythonPath) {
        $pythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Path
    }

    if ($pythonPath) {
        $pyScript = @"
import sqlite3, json
from datetime import datetime, timedelta

def win_time(t):
    try:
        if t and t > 0:
            return (datetime(1601,1,1) + timedelta(seconds=t)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        pass
    return '?'

conn = sqlite3.connect(r'$copyPath')
cur = conn.cursor()
cur.execute("""
    SELECT AppId, ActivityType, LastModifiedTime, Payload
    FROM Activity
    ORDER BY LastModifiedTime DESC
    LIMIT 500
""")
results = []
type_map = {5:'Open', 6:'AppInFocus', 10:'Clipboard', 11:'SystemEvent', 16:'AppSwitch'}
for appid_raw, atype, lmt, payload in cur.fetchall():
    app = '?'
    try:
        appid = json.loads(appid_raw)
        for entry in appid:
            if 'application' in entry:
                app = entry['application']
                break
    except:
        pass
    display = ''
    try:
        if payload:
            p = json.loads(payload)
            if isinstance(p, dict):
                display = p.get('displayText', p.get('description', ''))[:100]
    except:
        pass
    results.append({
        'ts': win_time(lmt),
        'app': app.split('!')[-1] if '!' in app else app,
        'display': display,
        'atype': type_map.get(atype, str(atype))
    })
conn.close()
print(json.dumps(results))
"@
        try {
            $pyResult = $pyScript | & $pythonPath - 2>$null
            if ($pyResult) {
                $activities = $pyResult | ConvertFrom-Json
                foreach ($a in $activities) {
                    $items += [pscustomobject]@{
                        Timestamp    = $a.ts
                        Application  = $a.app
                        DisplayText  = $a.display
                        ActivityType = $a.atype
                    }
                }
            }
        } catch {
            Write-Host "WARNING: Failed to parse timeline database - $_"
        }
    } else {
        Write-Host "WARNING: Python not found - cannot parse Activity History"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\windows_timeline.csv" -NoTypeInformation
        Write-Host "Timeline saved: $($items.Count) activities to $OutputPath\windows_timeline.csv"
    } else {
        Write-Host "(No timeline activities found)"
    }
    return $items
}

# Scans for gaming artifacts from Steam, Rimworld, Minecraft, and
# other game platforms.  Gaming data shows how the suspect spends
# their time, and common save file locations can also be used to
# hide data.
function Get-GameArtifacts {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Scanning for Game & Entertainment Artifacts ==="
    $items = @()

    # Steam registry
    try {
        $steamReg = Get-ItemProperty "HKCU:\Software\Valve\Steam" -ErrorAction SilentlyContinue
        if ($steamReg) {
            $steamPath = $steamReg.SteamPath
            $items += [pscustomobject]@{
                Source       = 'Steam'
                Name         = 'Steam Installation'
                Detail       = "Path: $steamPath | Installed: $(if (Test-Path $steamPath) {'Yes'} else {'Folder Missing'})"
                LastModified = 'N/A'
            }

            # Enumerate installed game ACF manifests
            $appsDir = "$steamPath\steamapps"
            if (Test-Path $appsDir) {
                Get-ChildItem "$appsDir\*.acf" -ErrorAction SilentlyContinue | ForEach-Object {
                    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    $gameName = if ($content -match '"name"\s+"([^"]+)"') { $matches[1] } else { $_.Name }
                    $items += [pscustomobject]@{
                        Source       = 'Steam'
                        Name         = $gameName
                        Detail       = "Manifest: $($_.Name)"
                        LastModified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                }
            }
        }
    } catch {}

    # Rimworld
    $rimworldPath = "$env:USERPROFILE\AppData\LocalLow\Ludeon Studios\RimWorld by Ludeon Studios"
    if (Test-Path $rimworldPath) {
        $items += [pscustomobject]@{
            Source       = 'Rimworld'
            Name         = 'Rimworld Data Found'
            Detail       = "Path: $rimworldPath"
            LastModified = (Get-Item $rimworldPath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $savesPath = "$rimworldPath\Saves"
        if (Test-Path $savesPath) {
            Get-ChildItem "$savesPath\*.rws" -ErrorAction SilentlyContinue | ForEach-Object {
                $sizeMB = [math]::Round($_.Length / 1MB, 1)
                $items += [pscustomobject]@{
                    Source       = 'Rimworld'
                    Name         = "Save: $($_.BaseName)"
                    Detail       = "Size: ${sizeMB}MB"
                    LastModified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
        # Check for mods
        $modLists = "$rimworldPath\ModLists"
        if (Test-Path $modLists) {
            $modCount = (Get-ChildItem $modLists -File -ErrorAction SilentlyContinue).Count
            if ($modCount -gt 0) {
                $items += [pscustomobject]@{
                    Source       = 'Rimworld'
                    Name         = 'Mod Lists'
                    Detail       = "$modCount mod list file(s)"
                    LastModified = (Get-ChildItem $modLists -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
    }

    # Minecraft
    if (Test-Path "$env:APPDATA\.minecraft") {
        $mcPath = "$env:APPDATA\.minecraft"
        $items += [pscustomobject]@{
            Source       = 'Minecraft'
            Name         = 'Minecraft Data Found'
            Detail       = "Path: $mcPath"
            LastModified = (Get-Item $mcPath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $mcSaves = "$mcPath\saves"
        if (Test-Path $mcSaves) {
            Get-ChildItem $mcSaves -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Source       = 'Minecraft'
                    Name         = "World: $($_.Name)"
                    Detail       = "Folder size not calculated"
                    LastModified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
    }

    # Epic Games
    $epicPath = "$env:LOCALAPPDATA\EpicGamesLauncher"
    if (Test-Path $epicPath) {
        $items += [pscustomobject]@{
            Source       = 'EpicGames'
            Name         = 'Epic Games Launcher'
            Detail       = "Path: $epicPath"
            LastModified = (Get-Item $epicPath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    # Discord (gaming social)
    $discordPath = "$env:APPDATA\discord"
    if (Test-Path $discordPath) {
        $items += [pscustomobject]@{
            Source       = 'Discord'
            Name         = 'Discord Data'
            Detail       = "Path: $discordPath"
            LastModified = (Get-Item $discordPath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\game_artifacts.csv" -NoTypeInformation
        Write-Host "Game artifacts saved: $($items.Count) items to $OutputPath\game_artifacts.csv"
    } else {
        Write-Host "(No game artifacts found)"
    }
    return $items
}