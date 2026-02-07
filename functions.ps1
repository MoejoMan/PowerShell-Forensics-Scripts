# Forensic Collection Functions

function Export-MemoryDump {
    param(
        [string]$OutputPath
    )
    Write-Output "=== Dumping RAM ==="
    $winpmem = "$PSScriptRoot\bin\winpmem\go-winpmem_amd64_1.0-rc2_signed.exe"
    
    if (Test-Path $winpmem) {
        try {
            $outputFile = "$OutputPath\memory_$(Get-Date -Format 'ddMMyyyy-HHmmss').raw"
            Write-Output "Acquiring memory... this may take a minute"
            & $winpmem "$outputFile" | Out-Null
            Write-Output "RAM saved to: $outputFile"
            return $true
        } catch {
            Write-Output "ERROR dumping RAM: $_"
            return $false
        }
    } else {
        Write-Output "ERROR: WinPmem not found at $winpmem"
        return $false
    }
}

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

function New-HTMLReport {
    param(
        [string]$OutputPath,
        [object]$Processes,
        [object]$Users,
        [object]$TCPConnections,
        [object]$Neighbors,
        [object]$PrefetchFiles
    )
    Write-Output "=== Generating HTML Report ==="
    
    try {
        # Convert objects to clean arrays, removing format objects
        if ($Processes) { $Processes = @($Processes | Where-Object { $_.Name -and $_.Id } | Select-Object Name, Id, CPU, WorkingSet, Path) }
        if ($Users) { $Users = @($Users | Where-Object { $_.Name } | Select-Object Name, Enabled, Description, LastLogon) }
        if ($TCPConnections) { $TCPConnections = @($TCPConnections | Where-Object { $_.LocalAddress } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State) }
        if ($Neighbors) { $Neighbors = @($Neighbors | Where-Object { $_.IPAddress } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias) }
        
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
        table { width: 100%; border-collapse: collapse; margin: 10px 0; background: white; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #ecf0f1; }
        details { margin: 15px 0; background: white; padding: 10px; border-radius: 5px; }
        summary { cursor: pointer; padding: 10px; background-color: #34495e; color: white; font-weight: bold; margin: -10px -10px 10px -10px; border-radius: 5px 5px 0 0; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
<h1>Digital Forensic Report</h1>
<p class="timestamp">Generated: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')</p>
<p class="timestamp">Host: $env:COMPUTERNAME | User: $env:USERNAME</p>

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