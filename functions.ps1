# Forensic Collection Functions

# ============================================================================
# MEMORY ACQUISITION
# ============================================================================
function Export-MemoryDump {
    param(
        [string]$OutputPath
    )

    Write-Output "=== Dumping RAM ==="
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
    Write-Output "=== Collecting Running Processes ==="
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
    Write-Output "=== Collecting Local User Accounts ==="
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
    Write-Output "=== Collecting TCP Connections ==="
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
    Write-Output "=== Collecting Network Neighbors (ARP) ==="
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
    Write-Output "=== Collecting Prefetch Files ==="
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
        [object]$RamResult,
        [object]$FileHashes
    )
    Write-Output "=== Generating HTML Report ==="
    
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
    Write-Output "=== Collecting Installed Programs ==="
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
    Write-Output "=== Collecting Services ==="
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
    Write-Output "=== Collecting Scheduled Tasks ==="
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName      = $_.TaskName
                TaskPath      = $_.TaskPath
                State         = $info.State
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
    Write-Output "=== Collecting Network Configuration ==="
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