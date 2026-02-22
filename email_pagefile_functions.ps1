# ============================================================================
# EMAIL ARTEFACT COLLECTION
# ============================================================================
# Collects email artefacts from Outlook, Thunderbird, and Windows Mail.
#
# For Outlook:
#   .pst = Personal Storage Table (local archive, can be opened in Outlook)
#   .ost = Offline Storage Table (cached Exchange/IMAP mailbox)
#   Both can be opened in Outlook or parsed with tools like pst-viewer,
#   readpst (Linux), or Kernel PST Viewer (free).
#
# For Thunderbird:
#   profile folder contains mbox files (plain text, one email per line
#   separated by "From " headers) - open directly or with Thunderbird.
#
# Why this matters for your case:
#   The brief says a victim granted access to emails linking the suspect
#   to the VMs. PST/OST files contain the full mailbox including deleted
#   items (Deleted Items folder persists until purged). Email headers
#   contain IP addresses, timestamps, and message-IDs that can be used
#   to link the suspect to extortion messages.
#
# NOTE: .ost files are often locked by a running Outlook process.
#       The function attempts a VSS fallback if direct copy fails.
function Get-EmailArtefacts {
    param(
        [string]$OutputPath
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Email Artefacts ==="

    $emailDir = Join-Path $OutputPath "email_artefacts"
    New-Item -ItemType Directory -Path $emailDir -Force | Out-Null

    $items = @()
    $profiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($prof in $profiles) {

        # â”€â”€ Outlook PST / OST files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Common locations across Outlook versions
        $outlookSearchPaths = @(
            (Join-Path $prof.FullName "Documents\Outlook Files"),
            (Join-Path $prof.FullName "AppData\Local\Microsoft\Outlook"),
            (Join-Path $prof.FullName "AppData\Roaming\Microsoft\Outlook")
        )

        foreach ($searchPath in $outlookSearchPaths) {
            if (-not (Test-Path $searchPath)) { continue }
            $mailFiles = Get-ChildItem $searchPath -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Extension -match '\.(pst|ost|nst)$' }

            foreach ($mf in $mailFiles) {
                $sizeMB = [math]::Round($mf.Length / 1MB, 1)
                $destDir = Join-Path $emailDir "$($prof.Name)_Outlook"
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                $dest = Join-Path $destDir $mf.Name

                $copyStatus = "Pending"
                try {
                    Copy-Item $mf.FullName $dest -Force -ErrorAction Stop
                    $copyStatus = "Copied"
                    Write-Host "  Copied $($mf.Extension.ToUpper()): $($mf.Name) ($sizeMB MB) for $($prof.Name)"
                } catch {
                    # File locked by Outlook - try esentutl, then shadow copy
                    Write-Host "  WARNING: $($mf.Name) is locked. Trying esentutl.exe /y /vss..."
                    $copied = $false

                    # Try esentutl first (built-in, no external tools)
                    try {
                        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
                        $esentResult = & esentutl.exe /y /vss $mf.FullName /d $dest 2>&1
                        if ($LASTEXITCODE -eq 0 -and (Test-Path $dest)) {
                            $copyStatus = "Copied (esentutl)"
                            $copied = $true
                            Write-Host "  Copied via esentutl: $($mf.Name)"
                        }
                    } catch {
                        Write-Host "  esentutl failed, trying shadow copy..."
                    }

                    # Fallback to shadow copy
                    if (-not $copied) {
                        try {
                            $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue |
                                       Sort-Object InstallDate -Descending
                            foreach ($shadow in $shadows) {
                                $shadowFile = $shadow.DeviceName + $mf.FullName.Substring(2)  # strip drive letter
                                if (Test-Path $shadowFile) {
                                    Copy-Item $shadowFile $dest -Force -ErrorAction Stop
                                    $copyStatus = "Copied (VSS)"
                                    $copied = $true
                                    Write-Host "  Copied via shadow copy: $($mf.Name)"
                                    break
                                }
                            }
                        } catch {
                            Write-Host "  Shadow copy also failed - $_"
                        }
                    }

                    if (-not $copied) {
                        $copyStatus = "Failed - locked, all methods exhausted"
                        Write-Host "  FAILED: $($mf.Name) - all copy methods failed"
                    }
                }

                $items += [pscustomobject]@{
                    User       = $prof.Name
                    Type       = $mf.Extension.ToUpper().TrimStart('.')
                    FileName   = $mf.Name
                    SourcePath = $mf.FullName
                    SizeMB     = $sizeMB
                    Modified   = $mf.LastWriteTime
                    CopyStatus = $copyStatus
                }
            }
        }

        # Also check registry for Outlook profile data store locations
        $outlookRegBase = "HKCU:\Software\Microsoft\Office"
        if (Test-Path $outlookRegBase) {
            try {
                Get-ChildItem $outlookRegBase -ErrorAction SilentlyContinue | ForEach-Object {
                    $profilesPath = Join-Path $_.PSPath "Outlook\Profiles"
                    if (Test-Path $profilesPath) {
                        Get-ChildItem $profilesPath -Recurse -ErrorAction SilentlyContinue |
                            Get-ItemProperty -ErrorAction SilentlyContinue |
                            ForEach-Object {
                                $pstPath = $_.PST
                                if ($pstPath -and (Test-Path $pstPath)) {
                                    $items += [pscustomobject]@{
                                        User       = $prof.Name
                                        Type       = 'PST_RegRef'
                                        FileName   = Split-Path $pstPath -Leaf
                                        SourcePath = $pstPath
                                        SizeMB     = [math]::Round((Get-Item $pstPath).Length / 1MB, 1)
                                        Modified   = (Get-Item $pstPath).LastWriteTime
                                        CopyStatus = 'Reference only'
                                    }
                                }
                            }
                    }
                }
            } catch { }
        }

        # â”€â”€ Thunderbird â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        $tbProfileRoot = Join-Path $prof.FullName "AppData\Roaming\Thunderbird\Profiles"
        if (Test-Path $tbProfileRoot) {
            $tbProfiles = Get-ChildItem $tbProfileRoot -Directory -ErrorAction SilentlyContinue
            foreach ($tbProf in $tbProfiles) {
                $tbDestDir = Join-Path $emailDir "$($prof.Name)_Thunderbird_$($tbProf.Name)"
                New-Item -ItemType Directory -Path $tbDestDir -Force | Out-Null

                # Copy mail folders (mbox files - no extension or .msf index files)
                $mailRoot = Join-Path $tbProf.FullName "Mail"
                $imapRoot = Join-Path $tbProf.FullName "ImapMail"

                foreach ($mailDir2 in @($mailRoot, $imapRoot)) {
                    if (Test-Path $mailDir2) {
                        try {
                            Copy-Item $mailDir2 $tbDestDir -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Host "  Copied Thunderbird mail folder for $($prof.Name): $mailDir2"
                        } catch {
                            Write-Host "  WARNING: Could not copy Thunderbird folder $mailDir2 - $_"
                        }
                    }
                }

                # Metadata summary
                $mboxFiles = Get-ChildItem $tbProf.FullName -Recurse -ErrorAction SilentlyContinue |
                             Where-Object { -not $_.PSIsContainer -and $_.Extension -eq '' -and $_.Length -gt 1KB }
                foreach ($mb in $mboxFiles) {
                    $items += [pscustomobject]@{
                        User       = $prof.Name
                        Type       = 'MBOX'
                        FileName   = $mb.Name
                        SourcePath = $mb.FullName
                        SizeMB     = [math]::Round($mb.Length / 1MB, 1)
                        Modified   = $mb.LastWriteTime
                        CopyStatus = 'Copied'
                    }
                }
            }
        }

        # â”€â”€ Windows Mail / Mail app â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        $winMailPath = Join-Path $prof.FullName "AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\Indexed"
        if (Test-Path $winMailPath) {
            $winMailDest = Join-Path $emailDir "$($prof.Name)_WindowsMail"
            New-Item -ItemType Directory -Path $winMailDest -Force | Out-Null
            try {
                Copy-Item $winMailPath $winMailDest -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  Copied Windows Mail data for $($prof.Name)"
                $items += [pscustomobject]@{
                    User       = $prof.Name
                    Type       = 'WindowsMail'
                    FileName   = 'Indexed (mail store)'
                    SourcePath = $winMailPath
                    SizeMB     = 'N/A'
                    Modified   = 'N/A'
                    CopyStatus = 'Copied'
                }
            } catch {
                Write-Host "  WARNING: Could not copy Windows Mail data - $_"
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv (Join-Path $OutputPath "email_artefacts.csv") -NoTypeInformation -Encoding UTF8
        Write-Host "  Email artefact summary: $($items.Count) items -> $OutputPath\email_artefacts.csv"
        Write-Host "  Raw files saved to: $emailDir"
        Write-Host ""
        Write-Host "  ANALYSIS TIPS:"
        Write-Host "    PST/OST : Open in Outlook, or use free Kernel PST Viewer"
        Write-Host "    MBOX    : Open directly in Thunderbird, or use 'readpst' on Linux"
        Write-Host "    Look for: Deleted Items, Sent Items, Drafts (unsent extortion msgs)"
        Write-Host "    Email headers contain originating IP addresses - critical for attribution"
    } else {
        Write-Host "  (No email artefacts found - no Outlook/Thunderbird/Windows Mail detected)"
    }

    return $items
}


# ============================================================================
# PAGEFILE AND HIBERNATION FILE COLLECTION
# ============================================================================
# pagefile.sys  - Windows virtual memory swap file. When RAM fills up,
#                 Windows writes process memory here. Can contain fragments
#                 of documents, passwords, decrypted file contents, and
#                 network traffic that was in RAM. Persists across reboots.
#
# hiberfil.sys  - Hibernation file. A compressed snapshot of ALL RAM at the
#                 moment hibernation occurred. Essentially a free memory dump.
#                 If the suspect hibernated rather than shut down, this is
#                 as valuable as a live RAM capture.
#                 Parse with: Volatility (treat as a memory image)
#                   vol.py -f hiberfil.sys --profile=Win10x64 windows.pslist
#
# swapfile.sys  - Modern Windows (8+) secondary swap for Metro/UWP apps.
#                 Smaller but may contain app data.
#
# NOTE: These files are system-locked and very large (pagefile = RAM size,
#       hiberfil = ~75% of RAM). Direct copy will fail.
#       This function uses three fallback strategies:
#         1. Shadow copy extraction
#         2. FTK Imager CLI (if available)
#         3. Raw handle approach via robocopy /B (backup mode)
function Get-PagefileAndHiberfil {
    param(
        [string]$OutputPath,
        [string]$ScriptRoot = $PSScriptRoot
    )

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Pagefile & Hibernation File ==="
    Write-Host "  WARNING: These files are large (several GB) and system-locked."
    Write-Host "  Collection may take several minutes."
    Write-Host ""

    $memFileDir = Join-Path $OutputPath "memory_files"
    New-Item -ItemType Directory -Path $memFileDir -Force | Out-Null

    $targets = @(
        @{ Name = 'pagefile.sys';  Path = "$env:SystemDrive\pagefile.sys";  Description = 'Virtual memory - may contain RAM fragments, passwords, document content' },
        @{ Name = 'hiberfil.sys';  Path = "$env:SystemDrive\hiberfil.sys";  Description = 'Hibernation image - full RAM snapshot, parse with Volatility' },
        @{ Name = 'swapfile.sys';  Path = "$env:SystemDrive\swapfile.sys";  Description = 'UWP app swap file' }
    )

    $results = @()

    foreach ($target in $targets) {
        $src  = $target.Path
        $dest = Join-Path $memFileDir $target.Name

        if (-not (Test-Path $src)) {
            Write-Host "  $($target.Name): not present on this system"
            $results += [pscustomobject]@{
                File        = $target.Name
                SizeMB      = 0
                Status      = 'Not present'
                Description = $target.Description
                Method      = 'N/A'
            }
            continue
        }

        $sizeMB = [math]::Round((Get-Item $src -ErrorAction SilentlyContinue).Length / 1MB, 0)
        Write-Host "  $($target.Name): $sizeMB MB - attempting collection..."

        $copied = $false
        $method = 'None'

        # â”€â”€ Strategy 1: esentutl.exe /y /vss (built-in Windows, most reliable) â”€
        if (-not $copied) {
            try {
                Write-Host "    Trying esentutl.exe /y /vss (built-in Windows)..."
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
                $esentResult = & esentutl.exe /y /vss $src /d $dest 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $dest)) {
                    $copied = $true
                    $method = 'esentutl /y /vss'
                    Write-Host "    Success via esentutl"
                } else {
                    Write-Host "    esentutl returned exit code $LASTEXITCODE"
                }
            } catch {
                Write-Host "    esentutl.exe failed - $_"
            }
        }

        # â”€â”€ Strategy 2: robocopy /B (backup privilege mode) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # /B = backup mode, bypasses file locks via SeBackupPrivilege
        # /J = unbuffered I/O (faster for large files)
        # /NP /NFL /NDL = quiet output
        if (-not $copied) {
            try {
                Write-Host "    Trying robocopy /B (backup mode)..."
                $roboArgs = "$env:SystemDrive\ `"$memFileDir`" $($target.Name) /B /J /NP /NFL /NDL /R:1 /W:1"
                $roboProc = Start-Process robocopy -ArgumentList $roboArgs -Wait -PassThru -NoNewWindow
                # robocopy exit codes 0-7 are success/partial success
                if ($roboProc.ExitCode -le 7 -and (Test-Path $dest)) {
                    $copied = $true
                    $method = 'robocopy /B'
                    Write-Host "    Success via robocopy /B"
                }
            } catch {
                Write-Host "    robocopy /B failed - $_"
            }
        }

        # â”€â”€ Strategy 3: Volume Shadow Copy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (-not $copied) {
            Write-Host "    Trying shadow copy..."
            try {
                $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue |
                           Sort-Object InstallDate -Descending
                foreach ($shadow in $shadows) {
                    # pagefile/hiberfil path in shadow: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\pagefile.sys
                    $shadowFile = $shadow.DeviceName + "\" + $target.Name
                    if (Test-Path $shadowFile) {
                        Copy-Item $shadowFile $dest -Force -ErrorAction Stop
                        $copied = $true
                        $method = 'Shadow copy'
                        Write-Host "    Success via shadow copy"
                        break
                    }
                }
            } catch {
                Write-Host "    Shadow copy failed - $_"
            }
        }

        # (FTK Imager CLI strategy removed - ftkimager.exe is a disk imaging tool, not a file copier)

        # â”€â”€ Result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (-not $copied) {
            # Last resort: try esentutl without /vss flag (sometimes works for non-ESE files)
            try {
                Write-Host "    Last resort: esentutl.exe /y (no VSS)..."
                $esentResult = & esentutl.exe /y $src /d $dest 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $dest)) {
                    $copied = $true
                    $method = 'esentutl /y'
                    Write-Host "    Success via esentutl (no VSS)"
                }
            } catch { }
        }

        if ($copied) {
            $copiedSizeMB = [math]::Round((Get-Item $dest).Length / 1MB, 0)
            Write-Host "  $($target.Name): collected ($copiedSizeMB MB) via $method -> $dest"

            if ($target.Name -eq 'hiberfil.sys') {
                Write-Host "  HIBERFIL TIP: This is a full RAM snapshot."
                Write-Host "    Convert: volatility -f hiberfil.sys imagecopy -O hiberfil.raw"
                Write-Host "    Then:    vol.py -f hiberfil.raw windows.pslist / windows.netscan"
            }
            if ($target.Name -eq 'pagefile.sys') {
                Write-Host "  PAGEFILE TIP: Use 'strings' to extract readable content:"
                Write-Host "    strings.exe -n 8 pagefile.sys | findstr /i '@' > emails_from_page.txt"
                Write-Host "    strings.exe -n 8 pagefile.sys | findstr /i 'password' > passwords.txt"
            }
        } else {
            Write-Host "  $($target.Name): FAILED - all strategies exhausted"
            Write-Host "  Manual collection required: use FTK Imager GUI to image the C: drive,"
            Write-Host "  then extract $($target.Name) from the image."
        }

        $results += [pscustomobject]@{
            File        = $target.Name
            SizeMB      = $sizeMB
            Status      = if ($copied) { "Collected ($method)" } else { 'Failed' }
            Description = $target.Description
            Method      = $method
        }
        Write-Host ""
    }

    $results | Export-Csv (Join-Path $OutputPath "memory_files_status.csv") -NoTypeInformation -Encoding UTF8
    Write-Host "  Status summary saved to: $OutputPath\memory_files_status.csv"
    Write-Host "  Files saved to: $memFileDir"

    return $results
}
