# Bypass execution policy, if missing, nothing will work
Set-ExecutionPolicy Bypass -Scope Process -Force

# Set root paths, so locations can be used later
$scriptRoot = $PSScriptRoot
$binPath = "$scriptRoot\bin"
$winpmem = "$binPath\Winpmem\winpmem_mini_x64_rc2.exe"

# Create output folders to dump data into them
$evidencePath = "$scriptRoot\evidence"
$transcriptPath = "$scriptRoot\transcript"
New-Item -ItemType Directory -Path $evidencePath, $transcriptPath -Force | Out-Null

# Start logging with our ACPO Principle 3 log
Start-Transcript -Path "$transcriptPath\collection_log.txt" -Append

try {
    # Check Secure Boot is running or its a blue screen for you!
    $secureSystem = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    Write-Host "Secure System Status: $($secureSystem.SecurityServicesRunning)"
    $confirm = Read-Host "Continue? (y/n)"
    if ($confirm -ne 'y') { exit }

    # Logging function
    function Write-Step($message) {
        Write-Host "[$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')] $message"
    }

     Go get the RAM before Chrome eats it all!
     Write-Step "Starting RAM dump..."
     if (Test-Path $winpmem) {
         & $winpmem "$evidencePath\memory.raw"
         Write-Step "RAM saved to evidence\memory.raw"
     } else {
         Write-Host "ERROR: Winpmem not found at $winpmem" -ForegroundColor Red
         exit
     }

# Go Get the User info!

# Processes
Write-Step "Collecting running processes..."
$processes = Get-Process | Select-Object Name, Id, CPU, Path
$processes | Export-Csv "$evidencePath\processes.csv" -NoTypeInformation
Write-Step "Saved processes to evidence\processes.csv"

# Local Users
Write-Step "Collecting user accounts..."
$users = Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon
$users | Export-Csv "$evidencePath\users.csv" -NoTypeInformation
Write-Step "Saved users to evidence\users.csv"

# Network TCP Connections
Write-Step "Collecting TCP connections..."
$tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
$tcpConnections | Export-Csv "$evidencePath\network_tcp.csv" -NoTypeInformation
Write-Step "Saved TCP connections to evidence\network_tcp.csv"

# Network Neighbors
Write-Step "Collecting network neighbors..."
$neighbors = Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
$neighbors | Export-Csv "$evidencePath\network_neighbors.csv" -NoTypeInformation
Write-Step "Saved network neighbors to evidence\network_neighbors.csv"

# Prefetch Files
Write-Step "Collecting prefetch files..."
$prefetch = Get-ChildItem C:\Windows\Prefetch\*.pf | Select-Object Name, LastWriteTime, Length
$prefetch | Export-Csv "$evidencePath\prefetch.csv" -NoTypeInformation
Write-Step "Saved prefetch list to evidence\prefetch.csv"

# Example
# Log-Step "Collecting SOMETHING"
# $ThingImCollecting = ThePowerShellCommand | Anything I want to filter
# $ThingImCollecting | Export-Csv "$evidencePath\NameOfItemBeingCollected.csv" -NoTypeInformation
# Log-Step "Saved TCP connections to evidence\NameOfItemBeingCollected.csv"

# Build HTML 
Write-Step "Building HTML report..."
$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        /* Keep existing styles */
        table { width: 100%; table-layout: fixed; }
        td { word-wrap: break-word; max-width: 300px; }
    </style>
</head>
<body>
<h1 style="color:rgb(21, 101, 65);">Digital Forensic Report</h1>
"@

# Processes Section
$html += @"
<details class="section">
    <summary>Running Processes ($($processes.Count) entries)</summary>
    $($processes | ConvertTo-Html -Fragment)
</details>
"@

# Users Section
$html += @"
<details class="section">
    <summary>User Accounts ($($users.Count) users)</summary>
    $($users | ConvertTo-Html -Fragment)
</details>
"@

# Network Section
$html += @"
<details class="section">
    <summary>Network Connections</summary>
    <h3>TCP Connections ($($tcpConnections.Count))</h3>
    $($tcpConnections | ConvertTo-Html -Fragment)
    <h3>Network Neighbors ($($neighbors.Count))</h3>
    $($neighbors | ConvertTo-Html -Fragment)
</details>
"@

# Prefetch Section
$html += @"
<details class="section">
    <summary>Prefetch Files ($($prefetch.Count) files)</summary>
    $($prefetch | ConvertTo-Html -Fragment)
</details>
"@

# Prefetch Section
#Allows an array to be used and store data from above
# $html += @" 
# <details class="section"> # makes a session for you
#     <summary>ThingImCollecting heading name ($($ThingImCollecting.Count) files)</summary> #name of data and how many items were collected
#     $($ThingImCollecting | ConvertTo-Html -Fragment) #converts to html
# </details>
# "@

$html += @"
</body>
</html>
"@

# Save report to a set location set below
$html | Out-File "$evidencePath\forensic_report.html" -Encoding UTF8
Write-Step "HTML report created with detailed data at evidence\forensic_report.html"
}
finally {
    Stop-Transcript
    Write-Host "Log saved to transcript\collection_log.txt"
}

# This script will do a very basic job of what you want it to do. You will need to go get some actual files though so make this easy use this as a base and add to it
# you want the actual prefetch files (not just a list), you can add image with a different script from outside the VM (targeting the VMDK). 
# Logs are good to get, but the tricky bit is getting a copy without corrupting it. Disks logically and physically are also helpful. (and others but check your slides and some research). Make sure to test the RAM dump with Vol.py please! Finally,see if you can get a copy of the MTF, J and Logfile. There is ways to do this with PowerForeniscs (without installing it) but it’s a bit advanced so if you have extra time give a go after doing the above.
