# Forensic Collection Functions

# ============================================================================
# MEMORY ACQUISITION
# ============================================================================
function Export-MemoryDump {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Dumping RAM ==="
    $result = [pscustomobject]@{
        Success = $false
        Path    = $null
        Error   = $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Output "WARNING: Not running as administrator; WinPmem may fail."
    }

    $candidatePaths = @(
        "bin\winpmem\go-winpmem_amd64_1.0-rc2_signed.exe",
        "bin\go-winpmem_amd64_1.0-rc2_signed.exe",
        "go-winpmem_amd64_1.0-rc2_signed.exe"
    ) | ForEach-Object { Join-Path -Path $PSScriptRoot -ChildPath $_ }

    $winpmem = $candidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $winpmem) {
        Write-Output "ERROR: WinPmem not found. Checked:"
        $candidatePaths | ForEach-Object { Write-Output "  $_" }
        $result.Error = "WinPmem not found"
        return $result
    }

    try {
        $outputFile = Join-Path $OutputPath "memory_$(Get-Date -Format 'ddMMyyyy-HHmmss').raw"
        Write-Output "Acquiring memory... this may take a minute"
        Write-Output "Using WinPmem: $winpmem"

        $winpmemOutput = & $winpmem acquire --progress "$outputFile" 2>&1
        $exitCode = $LASTEXITCODE

        if ($winpmemOutput) {
            Write-Output "WinPmem output:"
            $winpmemOutput | ForEach-Object { Write-Output "  $_" }
        }

        if ($exitCode -ne 0) {
            $result.Error = "WinPmem exit code $exitCode"
            return $result
        }

        if (Test-Path $outputFile) {
            $result.Success = $true
            $result.Path = $outputFile
            Write-Output "RAM saved to: $outputFile"
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
function Get-ProcessList {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Running Processes ==="
    try {
        $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path
        $processes | Format-Table -AutoSize
        $processes | Export-Csv "$OutputPath\processes.csv" -NoTypeInformation
        Write-Output "Processes saved to: $OutputPath\processes.csv"
        return $processes
    } catch {
        Write-Output "ERROR collecting processes: $_"
        return $null
    }
}

function Get-UserList {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Local User Accounts ==="
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon
        $users | Format-Table -AutoSize
        $users | Export-Csv "$OutputPath\users.csv" -NoTypeInformation
        Write-Output "Users saved to: $OutputPath\users.csv"
        return $users
    } catch {
        Write-Output "ERROR collecting users: $_"
        return $null
    }
}

function Get-NetworkConnections {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting TCP Connections ==="
    try {
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
        $tcpConnections | Format-Table -AutoSize
        $tcpConnections | Export-Csv "$OutputPath\network_tcp.csv" -NoTypeInformation
        Write-Output "TCP connections saved to: $OutputPath\network_tcp.csv"
        return $tcpConnections
    } catch {
        Write-Output "ERROR collecting TCP connections: $_"
        return $null
    }
}

function Get-NetworkNeighbors {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Network Neighbors (ARP) ==="
    try {
        $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
        $neighbors | Format-Table -AutoSize
        $neighbors | Export-Csv "$OutputPath\network_neighbors.csv" -NoTypeInformation
        Write-Output "Network neighbors saved to: $OutputPath\network_neighbors.csv"
        return $neighbors
    } catch {
        Write-Output "ERROR collecting network neighbors: $_"
        return $null
    }
}

function Get-PrefetchFiles {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Prefetch Files ==="
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Output "WARNING: Not running as administrator; Prefetch access may be blocked."
    }
    try {
        $prefetch = Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length
        
        if ($prefetch) {
            $prefetch | Format-Table -AutoSize
            $prefetch | Export-Csv "$OutputPath\prefetch.csv" -NoTypeInformation
            Write-Output "Prefetch files saved to: $OutputPath\prefetch.csv"
        } else {
            Write-Output "(No prefetch files found)"
        }
        return $prefetch
    } catch {
        Write-Output "ERROR collecting prefetch files: $_"
        return $null
    }
}

# ============================================================================
# HASHING AND INTEGRITY
# ============================================================================
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
        [object]$MemoryStrings
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Generating HTML Report ==="
    
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
        if ($Autoruns) { $Autoruns = @($Autoruns | Select-Object Location, Name, Command, Source) }
        if ($EventLogSecurity) { $EventLogSecurity = @($EventLogSecurity | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($EventLogSystem) { $EventLogSystem = @($EventLogSystem | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($EventLogApplication) { $EventLogApplication = @($EventLogApplication | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message) }
        if ($WmiPersistence) { $WmiPersistence = @($WmiPersistence | Select-Object Type, Name, QueryOrClass, Consumer, CommandLine, OtherFields) }
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
    <div class="card"><h4>Security Events</h4><p>$(@($EventLogSecurity).Count)</p></div>
    <div class="card"><h4>WMI Bindings</h4><p>$(@($WmiPersistence).Count)</p></div>
    <div class="card"><h4>ADS Found</h4><p>$(@($AlternateDataStreams).Count)</p></div>
    <div class="card"><h4>Hidden Files</h4><p>$(@($HiddenFiles).Count)</p></div>
    <div class="card"><h4>USB Devices</h4><p>$(@($USBDevices).Count)</p></div>
    <div class="card"><h4>Recycle Bin</h4><p>$(@($RecycleBin).Count)</p></div>
    <div class="card"><h4>DNS Cache</h4><p>$(@($DNSCache).Count)</p></div>
    <div class="card"><h4>RDP Sessions</h4><p>$(@($RDPSessions).Count)</p></div>
    <div class="card"><h4>Memory IOCs</h4><p>$(@($MemoryStrings).Count)</p></div>
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

            if (@($EventLogSecurity).Count -gt 0) {
                $html += @"
<h2>Security Log ($(@($EventLogSecurity).Count))</h2>
$(@($EventLogSecurity) | ConvertTo-Html -Fragment)
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
            $html += @"
<details open>
    <summary>Memory String Analysis ($(@($MemoryStrings).Count) IOCs)</summary>
    <p><em>IP addresses, emails, URLs, and bitcoin addresses extracted from the RAM dump.</em></p>
    $(@($MemoryStrings) | ConvertTo-Html -Fragment)
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
        Write-Output "HTML report saved to: $reportPath"
    } catch {
        Write-Output "ERROR generating HTML report: $_"
    }
}

function Get-InstalledPrograms {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Installed Programs ==="
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
            Write-Output "Installed programs saved to: $OutputPath\installed_programs.csv"
        } else {
            Write-Output "(No installed programs found)"
        }
        return $all
    } catch {
        Write-Output "ERROR collecting installed programs: $_"
        return $null
    }
}

function Get-ServicesList {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Services ==="
    try {
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
        if ($services) {
            $services | Export-Csv "$OutputPath\services.csv" -NoTypeInformation
            Write-Output "Services saved to: $OutputPath\services.csv"
        }
        return $services
    } catch {
        Write-Output "ERROR collecting services: $_"
        return $null
    }
}

function Get-ScheduledTasksList {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Scheduled Tasks ==="
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
            Write-Output "Scheduled tasks saved to: $OutputPath\tasks.csv"
        }
        return $tasks
    } catch {
        Write-Output "ERROR collecting scheduled tasks: $_"
        return $null
    }
}

function Get-NetworkConfig {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Network Configuration ==="
    try {
        $adapters = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, IPv4DefaultGateway
        if ($adapters) {
            $adapters | Export-Csv "$OutputPath\network_config.csv" -NoTypeInformation
            Write-Output "Network configuration saved to: $OutputPath\network_config.csv"
        }
        return $adapters
    } catch {
        Write-Output "ERROR collecting network configuration: $_"
        return $null
    }
}

function Get-EventLogTriage {
    param(
        [string]$OutputPath,
        [int]$Days = 3
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Event Log Triage ==="
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
                Write-Output "$logName events saved to: $target"
            } else {
                Write-Output "(No $logName events found in last $Days days)"
            }

            $results[$logName] = $events
        } catch {
            Write-Output "ERROR collecting $logName log: $_"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting WMI persistence (filters/consumers/bindings) ==="
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
        Write-Output "WARNING: Failed reading __EventFilter - $_"
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
        Write-Output "WARNING: Failed reading CommandLineEventConsumer - $_"
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
        Write-Output "WARNING: Failed reading ActiveScriptEventConsumer - $_"
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
        Write-Output "WARNING: Failed reading __FilterToConsumerBinding - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\wmi_persistence.csv" -NoTypeInformation
        Write-Output "WMI persistence saved to: $OutputPath\wmi_persistence.csv"
    } else {
        Write-Output "(No WMI persistence entries found)"
    }

    return $items
}

function Get-Autoruns {
    param(
        [string]$OutputPath
    )
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Autoruns (Run keys & Startup folders) ==="
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
                Write-Output "WARNING: Failed to read $path - $_"
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
                Write-Output "WARNING: Failed to read $dir - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\autoruns.csv" -NoTypeInformation
        Write-Output "Autoruns saved to: $OutputPath\autoruns.csv"
    } else {
        Write-Output "(No autoruns found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Scanning for Alternate Data Streams (ADS) ==="
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
                            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
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
            Write-Output "WARNING: ADS scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\alternate_data_streams.csv" -NoTypeInformation
        Write-Output "ADS results saved to: $OutputPath\alternate_data_streams.csv"
    } else {
        Write-Output "(No suspicious alternate data streams found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Scanning for Hidden & System Files ==="
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
                    ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -or
                    ($_.Attributes -band [System.IO.FileAttributes]::System)
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
            Write-Output "WARNING: Hidden-file scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\hidden_files.csv" -NoTypeInformation
        Write-Output "Hidden files saved to: $OutputPath\hidden_files.csv"
    } else {
        Write-Output "(No hidden/system files found in scanned paths)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Detecting Encrypted Volumes & Containers ==="
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
        Write-Output "WARNING: BitLocker query failed (may not be available) - $_"
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
        Write-Output "Encrypted volume info saved to: $OutputPath\encrypted_volumes.csv"
    } else {
        Write-Output "(No encrypted volumes or containers detected)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Zone.Identifier (Download Origins) ==="
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
                    $zi = Get-Content -Path $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
                    if ($zi) {
                        $zoneId   = ($zi | Select-String 'ZoneId=(\d)').Matches | ForEach-Object { $_.Groups[1].Value }
                        $hostUrl  = ($zi | Select-String 'HostUrl=(.+)').Matches | ForEach-Object { $_.Groups[1].Value }
                        $referrer = ($zi | Select-String 'ReferrerUrl=(.+)').Matches | ForEach-Object { $_.Groups[1].Value }

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
            Write-Output "WARNING: Zone.Identifier scan failed on $dir - $_"
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\zone_identifiers.csv" -NoTypeInformation
        Write-Output "Zone.Identifier data saved to: $OutputPath\zone_identifiers.csv"
    } else {
        Write-Output "(No Zone.Identifier data found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Recent File Activity (MRU / Recent Docs) ==="
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
        Write-Output "Recent file activity saved to: $OutputPath\recent_file_activity.csv"
    } else {
        Write-Output "(No recent file activity found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting USB Device History ==="
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
            Write-Output "WARNING: USBSTOR read failed - $_"
        }
    } else {
        Write-Output "(USBSTOR registry key not found)"
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
        Write-Output "USB device history saved to: $OutputPath\usb_device_history.csv"
    } else {
        Write-Output "(No USB device history found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Recycle Bin Contents ==="
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
        Write-Output "WARNING: Recycle Bin enumeration failed - $_"
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\recycle_bin.csv" -NoTypeInformation
        Write-Output "Recycle Bin contents saved to: $OutputPath\recycle_bin.csv"
    } else {
        Write-Output "(Recycle Bin is empty or inaccessible)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting DNS Cache ==="
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue |
            Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data
        if ($dns) {
            $dns | Export-Csv "$OutputPath\dns_cache.csv" -NoTypeInformation
            Write-Output "DNS cache saved to: $OutputPath\dns_cache.csv"
        } else {
            Write-Output "(DNS cache is empty)"
        }
        return $dns
    } catch {
        Write-Output "WARNING: DNS cache collection failed - $_"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Capturing Clipboard Contents ==="
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $clip = [System.Windows.Forms.Clipboard]::GetText()
        if ($clip) {
            $clip | Out-File "$OutputPath\clipboard.txt" -Encoding UTF8
            Write-Output "Clipboard contents saved to: $OutputPath\clipboard.txt"
        } else {
            Write-Output "(Clipboard is empty or contains non-text data)"
        }
        return $clip
    } catch {
        Write-Output "WARNING: Clipboard capture failed - $_"
        return $null
    }
}

# Captures mapped network drives and active SMB shares.  May reveal
# connections to other machines (the second VM) or exfiltration targets.
function Get-MappedDrivesAndShares {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Mapped Drives & Network Shares ==="
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
        Write-Output "Mapped drives/shares saved to: $OutputPath\mapped_drives_shares.csv"
    } else {
        Write-Output "(No mapped drives or shares found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting PowerShell Command History ==="
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
                Write-Output "WARNING: Could not read PS history for $($prof.Name) - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv "$OutputPath\powershell_history.csv" -NoTypeInformation
        Write-Output "PowerShell history saved to: $OutputPath\powershell_history.csv"
    } else {
        Write-Output "(No PowerShell history files found)"
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

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting RDP & Remote Session Artifacts ==="
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
        Write-Output "RDP/remote session data saved to: $OutputPath\rdp_remote_sessions.csv"
    } else {
        Write-Output "(No RDP or remote session artifacts found)"
    }
    return $items
}

# ============================================================================
# MEMORY ANALYSIS (POST-ACQUISITION)
# ============================================================================

# Logs the RAM dump details and advises the use of Volatility / strings.exe
# for proper structured memory analysis.  PowerShell is not suited for
# byte-level parsing of multi-GB raw dumps; purpose-built tools (Volatility,
# Rekall, strings.exe) handle this orders of magnitude faster and produce
# structured output (process trees, handles, injected code, etc.).
function Get-MemoryStrings {
    param(
        [string]$OutputPath,
        [string]$RamDumpPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Memory Dump Analysis Note ==="

    if (-not $RamDumpPath -or -not (Test-Path $RamDumpPath)) {
        Write-Output "(No RAM dump available)"
        return $null
    }

    $dumpItem = Get-Item $RamDumpPath
    $sizeMB   = [math]::Round($dumpItem.Length / 1MB, 2)

    Write-Output "RAM dump acquired: $($dumpItem.Name)"
    Write-Output "  Size: $sizeMB MB"
    Write-Output "  Path: $($dumpItem.FullName)"
    Write-Output ""
    Write-Output "RECOMMENDATION: Analyse this dump offline using Volatility 3 or strings.exe."
    Write-Output "  Volatility:  vol.py -f `"$RamDumpPath`" windows.pslist / windows.netscan / windows.filescan"
    Write-Output "  Strings:     strings.exe -n 6 `"$RamDumpPath`" | findstr /i `"@`" > emails.txt"
    Write-Output ""
    Write-Output "PowerShell is not practical for byte-level parsing of $sizeMB MB raw memory images."

    # Write the note to a file as well (so it appears in the evidence folder)
    $note = @"
MEMORY DUMP ANALYSIS NOTE
==========================
File:   $($dumpItem.Name)
Size:   $sizeMB MB
Path:   $($dumpItem.FullName)
Hash:   (see hashes.csv)

This RAM dump was acquired during live collection and should be analysed
using a purpose-built memory forensics tool:

  Volatility 3 (recommended):
    vol.py -f "$RamDumpPath" windows.pslist
    vol.py -f "$RamDumpPath" windows.netscan
    vol.py -f "$RamDumpPath" windows.filescan
    vol.py -f "$RamDumpPath" windows.cmdline

  SysInternals strings.exe:
    strings.exe -n 6 "$RamDumpPath" | findstr /i "@" > emails.txt
    strings.exe -n 6 "$RamDumpPath" | findstr /i "http" > urls.txt

PowerShell is not suited to byte-level parsing of large raw memory images.
The dump is preserved with SHA256 integrity hashing for chain of custody.
"@

    $note | Out-File "$OutputPath\memory_analysis_note.txt" -Encoding UTF8
    Write-Output "Note saved to: $OutputPath\memory_analysis_note.txt"

    return $null
}

# ============================================================================
# BROWSER ARTIFACTS & DOWNLOADS
# ============================================================================

function Get-BrowserArtifactsAndDownloads {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Browser Artifacts & Downloads (best effort) ==="
    $browserOut = Join-Path $OutputPath "browser_artifacts"
    New-Item -ItemType Directory -Path $browserOut -Force | Out-Null

    $downloadsFolder = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
    $downloads = $null
    if (Test-Path $downloadsFolder) {
        try {
            $downloads = Get-ChildItem -Path $downloadsFolder -File -ErrorAction SilentlyContinue | Select-Object Name, FullName, Length, LastWriteTime
            if ($downloads) {
                $downloads | Export-Csv "$OutputPath\downloads.csv" -NoTypeInformation
                Write-Output "Downloads listing saved to: $OutputPath\downloads.csv"
            }
        } catch {
            Write-Output "WARNING: Failed to enumerate Downloads - $_"
        }
    } else {
        Write-Output "(Downloads folder not found)"
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
