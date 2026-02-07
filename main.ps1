# Forensic Data Collection Script
Set-ExecutionPolicy Bypass -Scope Process -Force

# Import functions
. "$PSScriptRoot\functions.ps1"

# Set up output paths
$scriptRoot = $PSScriptRoot
$evidencePath = "$scriptRoot\Evidence"
$transcriptPath = "$scriptRoot\Transcript"
$htmlReportPath = "$scriptRoot\HTMLReport"

# Create output directories
New-Item -ItemType Directory -Path $evidencePath, $transcriptPath, $htmlReportPath -Force | Out-Null

# Set up logging (ACPO Principle 3 - Audit Trail)
$logFile = "$transcriptPath\collection_$(Get-Date -Format 'ddMMyyyy-HHmmss').log"
Start-Transcript -Path $logFile -Append

Write-Output "=========================================="
Write-Output "FORENSIC DATA COLLECTION"
Write-Output "=========================================="
Write-Output "Start Time: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
Write-Output ""

try {
    # CRITICAL: Dump RAM first (volatile data - gets overwritten!)
    Write-Output "PRIORITY 1: Capturing live RAM (volatile data)"
    Write-Output "If this fails, restart in forensic mode and try again"
    Write-Output ""
    $ramSuccess = Export-MemoryDump -OutputPath $evidencePath
    Write-Output ""
    
    if (-not $ramSuccess) {
        Write-Output "WARNING: RAM dump failed - continue with other collections"
    }
    
    # Now collect non-volatile data
    Write-Output "PRIORITY 2: Collecting system data"
    Write-Output ""
    
    $processes = Get-ProcessList -OutputPath $evidencePath
    Write-Output ""
    
    $users = Get-UserList -OutputPath $evidencePath
    Write-Output ""
    
    $tcpConnections = Get-NetworkConnections -OutputPath $evidencePath
    Write-Output ""
    
    $neighbors = Get-NetworkNeighbors -OutputPath $evidencePath
    Write-Output ""
    
    $prefetch = Get-PrefetchFiles -OutputPath $evidencePath
    Write-Output ""
    
    # Generate HTML report
    New-HTMLReport -OutputPath $htmlReportPath `
                        -Processes $processes `
                        -Users $users `
                        -TCPConnections $tcpConnections `
                        -Neighbors $neighbors `
                        -PrefetchFiles $prefetch
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
    Write-Output "  Evidence data: $evidencePath"
    Write-Output "  HTML report: $htmlReportPath\forensic_report.html"
    Write-Output "  Transcript log: $logFile"
    Write-Output "=========================================="
    
    Stop-Transcript
}