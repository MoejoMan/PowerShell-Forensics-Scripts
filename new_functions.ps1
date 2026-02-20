# ============================================================================
# FULL EVENT LOG EXPORT
# ============================================================================
# Exports ALL available events from Security, System, and Application logs
# to native .evtx format (preserving full fidelity for court) plus a CSV
# triage of the most forensically relevant event IDs.
#
# Replaces Get-EventLogTriage for full coverage.
# The -Days parameter on the old function is dropped; we take everything.
#
# Key forensic Event IDs collected in triage CSV:
#   Security: 4624/4625 (logon/fail), 4634/4647 (logoff), 4648 (explicit creds),
#             4672 (admin logon), 4688 (process create), 4698/4702 (scheduled task),
#             4720/4726 (account created/deleted), 4771/4776 (Kerberos)
#   System:   7034/7036/7040/7045 (service events), 6005/6006/6008 (boot/shutdown)
#   Application: 1000/1001/1002 (app crash/hang)
function Get-FullEventLogs {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Exporting Full Event Logs ==="
    Write-Host "This exports ALL events (no date filter) - may take a minute on large logs."

    $evtxDir = Join-Path $OutputPath "evtx"
    New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null

    # â”€â”€ Forensically significant Event IDs per log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $triageIds = @{
        Security    = @(
            4624, 4625, 4634, 4647, 4648, 4672, 4673, 4688, 4689,
            4698, 4702, 4703, 4720, 4722, 4724, 4726, 4728, 4732,
            4756, 4771, 4776, 4778, 4779, 4800, 4801, 5140, 5145
        )
        System      = @(6005, 6006, 6008, 6013, 7034, 7036, 7040, 7045, 104)
        Application = @(1000, 1001, 1002)
    }

    $results = @{}

    foreach ($logName in @('Security', 'System', 'Application')) {

        # â”€â”€ 1. Export raw .evtx (full fidelity for Volatility / Event Viewer) â”€â”€
        $evtxOut = Join-Path $evtxDir "$logName.evtx"
        try {
            $wevtArgs = @(
                "epl",               # export-log
                $logName,            # source log
                $evtxOut,            # destination file
                "/ow:true"           # overwrite if exists
            )
            & wevtutil.exe @wevtArgs 2>&1 | Out-Null
            $sizeMB = [math]::Round((Get-Item $evtxOut -ErrorAction SilentlyContinue).Length / 1MB, 1)
            Write-Host "  Exported $logName.evtx ($sizeMB MB) -> $evtxOut"
        } catch {
            Write-Host "  WARNING: wevtutil export failed for $logName - $_"
        }

        # â”€â”€ 2. CSV triage of key event IDs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        $csvOut = Join-Path $OutputPath "event_${logName}_full.csv"
        try {
            $ids = $triageIds[$logName]
            $filterHash = @{ LogName = $logName; Id = $ids }
            $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName,
                    @{ N='Message'; E={ $_.Message -replace '\s+', ' ' } }

            if ($events) {
                $events | Export-Csv $csvOut -NoTypeInformation -Encoding UTF8
                Write-Host "  Triage CSV: $($events.Count) key events -> $csvOut"
            } else {
                Write-Host "  (No key event IDs found in $logName)"
            }
            $results[$logName] = $events
        } catch {
            Write-Host "  WARNING: Triage CSV failed for $logName - $_"
            $results[$logName] = $null
        }
    }

    Write-Host ""
    Write-Host "  .evtx files saved to: $evtxDir"
    Write-Host "  Open .evtx in Windows Event Viewer or use Volatility for full analysis."

    return [pscustomobject]@{
        Security    = $results.Security
        System      = $results.System
        Application = $results.Application
    }
}


# ============================================================================
# MULTI-VM BATCH AUTOMATION
# ============================================================================
# Runs the full collection pipeline against multiple VMs in sequence.
# Each VM gets its own evidence folder, transcript, and HTML report,
# all labelled with the VM name for ACPO evidence separation.
#
# Usage (from run.bat or directly):
#   powershell -ExecutionPolicy Bypass -File main.ps1 -BatchMode
#
# The function prompts for:
#   - How many VMs to process
#   - A label for each (e.g. VM1_Live, VM2_Sleeping)
#   - Whether to skip RAM dump per VM (e.g. sleeping VM has no live RAM)
#
# After all VMs are processed it prints a summary table.
function Invoke-MultiVMCollection {
    param(
        [string]$ScriptRoot,
        [string]$BaseOutputPath
    )

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  MULTI-VM BATCH COLLECTION MODE"
    Write-Host "=========================================="
    Write-Host ""

    # â”€â”€ Gather VM targets interactively â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $vmCount = 0
    while ($vmCount -lt 1 -or $vmCount -gt 10) {
        $vmCountInput = Read-Host "How many VMs do you want to process? (1-10)"
        if ($vmCountInput -match '^\d+$') { $vmCount = [int]$vmCountInput }
    }

    $vmTargets = @()
    for ($i = 1; $i -le $vmCount; $i++) {
        Write-Host ""
        Write-Host "--- VM $i of $vmCount ---"
        $label = ""
        while (-not $label) {
            $label = (Read-Host "  Label for VM $i (e.g. VM1_Live, VM2_Sleeping)").Trim()
            $label = $label -replace '[^a-zA-Z0-9_-]', '_'
        }

        $skipRam = $false
        $ramChoice = Read-Host "  Skip RAM dump for $label? (Y/N) [N for live VMs, Y for sleeping/offline]"
        if ($ramChoice -match '^[Yy]') { $skipRam = $true }

        $skipHashes = $false
        $hashChoice = Read-Host "  Skip file hashing for $label? (Y/N) [Hashing adds ~1 min]"
        if ($hashChoice -match '^[Yy]') { $skipHashes = $true }

        $vmTargets += [pscustomobject]@{
            Label      = $label
            SkipRam    = $skipRam
            SkipHashes = $skipHashes
            Status     = 'Pending'
            StartTime  = $null
            EndTime    = $null
            EvidencePath = $null
        }
    }

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  Starting batch collection..."
    Write-Host "  VMs to process: $($vmTargets | ForEach-Object { $_.Label } | Join-String -Separator ', ')"
    Write-Host "=========================================="
    Write-Host ""

    # â”€â”€ Process each VM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    foreach ($vm in $vmTargets) {
        Write-Host ""
        Write-Host "=========================================="
        Write-Host "  Processing: $($vm.Label)"
        Write-Host "  Time: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
        Write-Host "=========================================="

        $vm.StartTime = Get-Date

        # Re-invoke the main script for this VM label by dot-sourcing
        # the same functions and running the full pipeline inline.
        # This keeps a single transcript per VM.
        try {
            $subArgs = @(
                "-ExecutionPolicy", "Bypass",
                "-File", "$ScriptRoot\main.ps1",
                "-VmLabel", $vm.Label
            )
            if ($vm.SkipRam)    { $subArgs += "-SkipRamDump" }
            if ($vm.SkipHashes) { $subArgs += "-SkipHashes" }

            # Launch as a new elevated process and wait for it
            $proc = Start-Process powershell -ArgumentList $subArgs -Verb RunAs -Wait -PassThru

            if ($proc.ExitCode -eq 0) {
                $vm.Status = 'Complete'
            } else {
                $vm.Status = "Failed (exit $($proc.ExitCode))"
            }
        } catch {
            $vm.Status = "Error: $_"
        }

        $vm.EndTime = Get-Date
        $vm.EvidencePath = Join-Path $BaseOutputPath "Evidence\$($vm.Label)"

        $duration = [math]::Round(($vm.EndTime - $vm.StartTime).TotalMinutes, 1)
        Write-Host "  Finished $($vm.Label) in $duration min - Status: $($vm.Status)"

        # Pause between VMs so the investigator can switch VM context
        # (e.g. wake sleeping VM, move USB drive, etc.)
        if ($vm -ne $vmTargets[-1]) {
            Write-Host ""
            Write-Host "  --- Ready for next VM ---"
            Read-Host "  Press ENTER when you have switched to the next VM and are ready to continue"
        }
    }

    # â”€â”€ Summary table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  BATCH COLLECTION SUMMARY"
    Write-Host "=========================================="
    $vmTargets | Format-Table Label, Status,
        @{ N='Duration'; E={ "$([math]::Round(($_.EndTime - $_.StartTime).TotalMinutes,1)) min" } },
        @{ N='Evidence'; E={ $_.EvidencePath } } -AutoSize

    # Return results for HTML report
    return $vmTargets
}
