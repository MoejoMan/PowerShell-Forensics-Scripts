# ============================================================================
# REGISTRY HIVE COLLECTION
# ============================================================================
# Exports live registry hives using `reg save`. These are binary .hiv files
# that can be loaded into tools like Registry Explorer, RegRipper, or
# forensic suites for full offline analysis.
#
# Hives collected:
#   SAM      - Local user accounts and password hashes
#   SYSTEM   - Hardware config, timezone, USB history, network interfaces
#   SOFTWARE - Installed programs, autorun entries, OS settings
#   SECURITY - LSA secrets, cached credentials (admin only)
#   NTUSER   - Per-user settings, MRU lists, typed paths, UserAssist
#   UsrClass - User-specific COM/shell settings, bag keys (folder access)
#
# Why this matters: Even after files are deleted, registry hives can retain
# evidence of programs run, files opened, and USB devices connected.
function Get-RegistryHives {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Registry Hives ==="

    $hivesDir = Join-Path $OutputPath "registry_hives"
    New-Item -ItemType Directory -Path $hivesDir -Force | Out-Null

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Output "WARNING: Not running as administrator. SAM and SECURITY hives will likely fail."
    }

    # System hives (require admin)
    $systemHives = @{
        'SAM'      = 'HKLM\SAM'
        'SYSTEM'   = 'HKLM\SYSTEM'
        'SOFTWARE' = 'HKLM\SOFTWARE'
        'SECURITY' = 'HKLM\SECURITY'
    }

    foreach ($hive in $systemHives.GetEnumerator()) {
        $dest = Join-Path $hivesDir "$($hive.Key).hiv"
        try {
            # reg save fails if destination exists - remove first
            if (Test-Path $dest) { Remove-Item $dest -Force }
            $output = & reg save $hive.Value $dest /y 2>&1
            if (Test-Path $dest) {
                $sizeMB = [math]::Round((Get-Item $dest).Length / 1MB, 2)
                Write-Output "  Saved $($hive.Key).hiv ($sizeMB MB)"
            } else {
                Write-Output "  WARNING: $($hive.Key) - reg save reported: $output"
            }
        } catch {
            Write-Output "  ERROR saving $($hive.Key): $_"
        }
    }

    # Per-user hives (NTUSER.DAT and UsrClass.dat for each profile)
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($prof in $profiles) {
        # NTUSER.DAT
        $ntuserSrc = Join-Path $prof.FullName "NTUSER.DAT"
        $ntuserDst = Join-Path $hivesDir "NTUSER_$($prof.Name).DAT"
        if (Test-Path $ntuserSrc) {
            try {
                Copy-Item $ntuserSrc $ntuserDst -Force -ErrorAction Stop
                $sizeMB = [math]::Round((Get-Item $ntuserDst).Length / 1MB, 2)
                Write-Output "  Copied NTUSER.DAT for $($prof.Name) ($sizeMB MB)"
            } catch {
                # File is locked - use Volume Shadow Copy trick or reg save
                try {
                    $regPath = "HKU\$($prof.Name)_TEMP"
                    & reg load $regPath $ntuserSrc 2>&1 | Out-Null
                    if (Test-Path $ntuserDst) { Remove-Item $ntuserDst -Force }
                    & reg save $regPath $ntuserDst /y 2>&1 | Out-Null
                    & reg unload $regPath 2>&1 | Out-Null
                    if (Test-Path $ntuserDst) {
                        Write-Output "  Saved NTUSER.DAT for $($prof.Name) via reg load/save"
                    } else {
                        Write-Output "  WARNING: Could not export NTUSER.DAT for $($prof.Name) (file locked)"
                    }
                } catch {
                    Write-Output "  WARNING: NTUSER.DAT locked for $($prof.Name) - collect via VSS or offline"
                }
            }
        }

        # UsrClass.dat
        $usrClassSrc = Join-Path $prof.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
        $usrClassDst = Join-Path $hivesDir "UsrClass_$($prof.Name).dat"
        if (Test-Path $usrClassSrc) {
            try {
                Copy-Item $usrClassSrc $usrClassDst -Force -ErrorAction Stop
                Write-Output "  Copied UsrClass.dat for $($prof.Name)"
            } catch {
                Write-Output "  WARNING: UsrClass.dat locked for $($prof.Name)"
            }
        }
    }

    Write-Output "  Registry hives saved to: $hivesDir"
    Write-Output "  TIP: Load .hiv files in Registry Explorer (Eric Zimmermann) for full analysis."
    Write-Output "  TIP: Run RegRipper against NTUSER.DAT for automated artefact extraction."

    return $hivesDir
}


# ============================================================================
# SRUM DATABASE (System Resource Usage Monitor)
# ============================================================================
# Copies the SRUM database (SRUDB.dat). SRUM records every application's
# network bytes sent/received, CPU time, and energy usage with timestamps
# going back ~30 days. This persists even after browser history is cleared
# and can prove network exfiltration activity at specific times.
#
# Parse offline with: SrumECmd.exe (Eric Zimmermann) or srum-dump
function Get-SRUMDatabase {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting SRUM Database ==="

    $srumSrc = "C:\Windows\System32\sru\SRUDB.dat"
    $srumDst = Join-Path $OutputPath "SRUDB.dat"

    if (-not (Test-Path $srumSrc)) {
        Write-Output "  (SRUM database not found at $srumSrc)"
        return $null
    }

    try {
        Copy-Item $srumSrc $srumDst -Force -ErrorAction Stop
        $sizeMB = [math]::Round((Get-Item $srumDst).Length / 1MB, 2)
        Write-Output "  SRUM database copied ($sizeMB MB) -> $srumDst"
        Write-Output "  Parse with: SrumECmd.exe -f `"$srumDst`" --csv output_folder"
    } catch {
        # File is locked by svchost - use VSS or raw copy fallback
        Write-Output "  WARNING: SRUDB.dat is locked. Attempting shadow copy fallback..."
        try {
            $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadows) {
                $shadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
                $shadowPath = $shadow.DeviceName + "\Windows\System32\sru\SRUDB.dat"
                Copy-Item $shadowPath $srumDst -Force -ErrorAction Stop
                Write-Output "  SRUM database copied from shadow copy -> $srumDst"
            } else {
                Write-Output "  ERROR: No shadow copies available. SRUM must be collected offline."
            }
        } catch {
            Write-Output "  ERROR: Could not copy SRUDB.dat - $_"
            Write-Output "  Collect manually using FTK Imager or offline analysis."
        }
    }

    return $srumDst
}


# ============================================================================
# AMCACHE AND SHIMCACHE (Program Execution Evidence)
# ============================================================================
# Amcache.hve records SHA1 hashes of every executable run on the system,
# even if the file has since been deleted. Critical for proving a program
# was executed without needing the file itself.
#
# AppCompatCache (ShimCache) in the SYSTEM hive records execution order
# and timestamps for compatibility checks - another execution artefact.
#
# Parse Amcache with: AmcacheParser.exe (Eric Zimmermann)
function Get-AmcacheAndShimcache {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Amcache & ShimCache ==="

    $amcacheSrc = "C:\Windows\AppCompat\Programs\Amcache.hve"
    $amcacheDst = Join-Path $OutputPath "Amcache.hve"

    if (Test-Path $amcacheSrc) {
        try {
            Copy-Item $amcacheSrc $amcacheDst -Force -ErrorAction Stop
            $sizeMB = [math]::Round((Get-Item $amcacheDst).Length / 1MB, 2)
            Write-Output "  Amcache.hve copied ($sizeMB MB) -> $amcacheDst"
            Write-Output "  Parse with: AmcacheParser.exe -f `"$amcacheDst`" --csv output_folder"
        } catch {
            Write-Output "  WARNING: Amcache.hve locked - attempting shadow copy..."
            try {
                $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
                if ($shadows) {
                    $shadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
                    $shadowPath = $shadow.DeviceName + "\Windows\AppCompat\Programs\Amcache.hve"
                    Copy-Item $shadowPath $amcacheDst -Force -ErrorAction Stop
                    Write-Output "  Amcache.hve copied from shadow copy"
                } else {
                    Write-Output "  ERROR: Amcache.hve locked and no shadow copies available"
                }
            } catch {
                Write-Output "  ERROR: Could not copy Amcache.hve - $_"
            }
        }
    } else {
        Write-Output "  (Amcache.hve not found - may be older Windows version)"
    }

    # ShimCache lives in SYSTEM hive - export just that key as a readable dump
    Write-Output "  Extracting ShimCache entries from registry..."
    $shimItems = @()
    try {
        $shimPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
        if (Test-Path $shimPath) {
            # The raw binary data requires offline parsing (AppCompatCacheParser)
            # We note it here and flag for offline analysis
            $shimData = Get-ItemProperty -Path $shimPath -ErrorAction SilentlyContinue
            if ($shimData.AppCompatCache) {
                $sizeBytes = $shimData.AppCompatCache.Length
                $shimItems += [pscustomobject]@{ DataSize = $sizeBytes; Source = 'AppCompatCache'; Note = 'Requires offline parsing' }
                Write-Output "  ShimCache raw data found ($sizeBytes bytes) - saved in SYSTEM.hiv"
                Write-Output "  Parse with: AppCompatCacheParser.exe -f SYSTEM.hiv --csv output_folder"
            }
        }
    } catch {
        Write-Output "  WARNING: ShimCache read failed - $_"
    }
    # Export ShimCache metadata if any entries found
    if ($shimItems.Count -gt 0) {
        $shimItems | Export-Csv (Join-Path $amcacheDir 'shimcache_metadata.csv') -NoTypeInformation
    }

    return $amcacheDst
}


# ============================================================================
# LNK FILES AND JUMP LISTS
# ============================================================================
# LNK (shortcut) files are created automatically by Windows every time a
# file is opened. They contain the original file path, MAC timestamps, volume
# serial number, and sometimes the target machine name - even if the original
# file no longer exists. Jump lists extend this with per-application MRU lists.
#
# Parse with: LECmd.exe and JLECmd.exe (Eric Zimmermann)
function Get-LnkAndJumpLists {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting LNK Files & Jump Lists ==="

    $lnkDir = Join-Path $OutputPath "lnk_jumplists"
    New-Item -ItemType Directory -Path $lnkDir -Force | Out-Null

    $items = @()
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($prof in $profiles) {

        # Recent LNK files
        $recentDir = Join-Path $prof.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $recentDir) {
            $lnkFiles = Get-ChildItem $recentDir -Filter "*.lnk" -ErrorAction SilentlyContinue
            $profLnkDir = Join-Path $lnkDir "$($prof.Name)_Recent"
            if ($lnkFiles) {
                New-Item -ItemType Directory -Path $profLnkDir -Force | Out-Null
                foreach ($f in $lnkFiles) {
                    try {
                        Copy-Item $f.FullName $profLnkDir -Force -ErrorAction SilentlyContinue
                        # Parse basic metadata from LNK using Shell COM object
                        $shell = New-Object -ComObject WScript.Shell -ErrorAction SilentlyContinue
                        $shortcut = $shell.CreateShortcut($f.FullName)
                        $items += [pscustomobject]@{
                            User         = $prof.Name
                            Type         = 'RecentLNK'
                            LnkName      = $f.Name
                            TargetPath   = $shortcut.TargetPath
                            LnkCreated   = $f.CreationTime
                            LnkModified  = $f.LastWriteTime
                            Arguments    = $shortcut.Arguments
                        }
                    } catch { }
                }
                Write-Output "  Copied $($lnkFiles.Count) LNK files for $($prof.Name)"
            }
        }

        # Jump Lists (AutomaticDestinations + CustomDestinations)
        foreach ($jlFolder in @('AutomaticDestinations', 'CustomDestinations')) {
            $jlDir = Join-Path $prof.FullName "AppData\Roaming\Microsoft\Windows\Recent\$jlFolder"
            if (Test-Path $jlDir) {
                $jlFiles = Get-ChildItem $jlDir -ErrorAction SilentlyContinue
                if ($jlFiles) {
                    $destDir = Join-Path $lnkDir "$($prof.Name)_$jlFolder"
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                    $jlFiles | ForEach-Object {
                        try { Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue } catch { }
                    }
                    Write-Output "  Copied $($jlFiles.Count) $jlFolder files for $($prof.Name)"
                }
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv (Join-Path $OutputPath "lnk_metadata.csv") -NoTypeInformation
        Write-Output "  LNK metadata CSV: $($items.Count) entries -> $OutputPath\lnk_metadata.csv"
    }

    Write-Output "  Raw LNK/JumpList files saved to: $lnkDir"
    Write-Output "  Parse with: LECmd.exe -d `"$lnkDir`" --csv output_folder"
    Write-Output "  Parse with: JLECmd.exe -d `"$lnkDir`" --csv output_folder"

    return $items
}


# ============================================================================
# THUMBNAIL CACHE
# ============================================================================
# Windows caches thumbnails of viewed images, videos, and documents in
# thumbcache_*.db files. These can retain thumbnails of files that have
# since been deleted - potentially showing images the suspect viewed
# even after they cleared their downloads or recycle bin.
#
# Parse with: Thumbcache Viewer (free tool) or ThumbcacheParser
function Get-ThumbnailCache {
    param(
        [string]$OutputPath
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Thumbnail Cache ==="

    $thumbDir = Join-Path $OutputPath "thumbnail_cache"
    New-Item -ItemType Directory -Path $thumbDir -Force | Out-Null

    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    $copied = 0

    foreach ($prof in $profiles) {
        $cacheDir = Join-Path $prof.FullName "AppData\Local\Microsoft\Windows\Explorer"
        if (Test-Path $cacheDir) {
            $thumbFiles = Get-ChildItem $cacheDir -Filter "thumbcache_*.db" -ErrorAction SilentlyContinue
            foreach ($f in $thumbFiles) {
                try {
                    $dest = Join-Path $thumbDir "$($prof.Name)_$($f.Name)"
                    Copy-Item $f.FullName $dest -Force -ErrorAction Stop
                    $copied++
                } catch {
                    Write-Output "  WARNING: Could not copy $($f.Name) for $($prof.Name) - $_"
                }
            }
            if ($thumbFiles) {
                Write-Output "  Copied $($thumbFiles.Count) thumbcache files for $($prof.Name)"
            }
        }
    }

    if ($copied -gt 0) {
        Write-Output "  $copied thumbcache files saved to: $thumbDir"
        Write-Output "  Parse with: Thumbcache Viewer - https://thumbcacheviewer.github.io"
    } else {
        Write-Output "  (No thumbnail cache files found)"
    }

    return $thumbDir
}


# ============================================================================
# MFT AND USN JOURNAL COLLECTION (via fsutil + external tool)
# ============================================================================
# The Master File Table ($MFT) is the index of every file on an NTFS volume.
# Even deleted file entries persist in the MFT until overwritten, preserving
# filename, timestamps, size, and parent directory.
#
# The USN Change Journal ($UsnJrnl) records every file system operation
# (create, modify, rename, delete) - critical for proving a file existed
# and was then deleted.
#
# PowerShell cannot read $MFT directly (NTFS metadata file).
# This function uses two approaches:
#   1. fsutil usn - exports USN journal entries (no extra tools needed)
#   2. If RawCopy or MFTECmd is present in the bin\ folder, uses that for $MFT
function Get-MFTAndUsnJournal {
    param(
        [string]$OutputPath,
        [string]$ScriptRoot = $PSScriptRoot
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Collecting MFT & USN Journal ==="

    $mftDir = Join-Path $OutputPath "mft_usn"
    New-Item -ItemType Directory -Path $mftDir -Force | Out-Null

    # ── 1. USN Journal via fsutil (no extra tools needed) ───────────────────
    Write-Output "  Exporting USN Journal via fsutil..."
    try {
        $usnOut = Join-Path $mftDir "usn_journal.csv"
        $usnRaw = & fsutil usn readjournal C: csv 2>&1
        if ($usnRaw -and $LASTEXITCODE -eq 0) {
            $usnRaw | Out-File $usnOut -Encoding UTF8
            Write-Output "  USN Journal exported -> $usnOut"
        } else {
            Write-Output "  WARNING: fsutil usn failed - $usnRaw"
        }
    } catch {
        Write-Output "  WARNING: USN Journal export failed - $_"
    }

    # ── 2. $MFT via RawCopy or MFTECmd if available in bin\ ─────────────────
    $rawCopyPaths = @(
        (Join-Path $ScriptRoot "bin\RawCopy\RawCopy.exe"),
        (Join-Path $ScriptRoot "bin\RawCopy64.exe"),
        (Join-Path $ScriptRoot "bin\RawCopy.exe")
    )
    $rawCopy = $rawCopyPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    $mftEcmdPaths = @(
        (Join-Path $ScriptRoot "bin\MFTECmd.exe"),
        (Join-Path $ScriptRoot "bin\MFTECmd\MFTECmd.exe")
    )
    $mftEcmd = $mftEcmdPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($rawCopy) {
        Write-Output "  RawCopy found - extracting `$MFT..."
        try {
            $mftDest = Join-Path $mftDir "MFT"
            & $rawCopy /FileNamePath:C:\`$MFT /OutputPath:$mftDir 2>&1 | ForEach-Object { Write-Output "  $_" }
            if (Test-Path $mftDest) {
                $sizeMB = [math]::Round((Get-Item $mftDest).Length / 1MB, 1)
                Write-Output "  `$MFT extracted ($sizeMB MB) -> $mftDest"
            }
        } catch {
            Write-Output "  ERROR: RawCopy failed - $_"
        }
    } elseif ($mftEcmd) {
        Write-Output "  MFTECmd found - parsing `$MFT directly..."
        try {
            $mftCsvOut = Join-Path $mftDir "mft_parsed"
            New-Item -ItemType Directory -Path $mftCsvOut -Force | Out-Null
            & $mftEcmd -f C:\`$MFT --csv $mftCsvOut 2>&1 | ForEach-Object { Write-Output "  $_" }
            Write-Output "  `$MFT parsed -> $mftCsvOut"
        } catch {
            Write-Output "  ERROR: MFTECmd failed - $_"
        }
    } else {
        Write-Output "  NOTE: Neither RawCopy nor MFTECmd found in bin\ folder."
        Write-Output "  To collect `$MFT, add one of these to your USB:"
        Write-Output "    RawCopy64.exe: https://github.com/jschicht/RawCopy"
        Write-Output "    MFTECmd.exe  : https://ericzimmermann.com/get-zimtools (free)"
        Write-Output "  Then place in: $ScriptRoot\bin\"
        Write-Output ""
        Write-Output "  Alternatively, FTK Imager can export `$MFT from a live or offline volume."

        # Write the note to evidence folder
        @"
MFT COLLECTION NOTE
===================
The $MFT could not be automatically extracted because neither RawCopy
nor MFTECmd was found in the bin\ folder.

To collect MFT manually:
  Option 1 - FTK Imager (GUI):
    File > Add Evidence Item > Logical Drive > C:
    Expand tree > [root] > right-click `$MFT > Export Files

  Option 2 - Add RawCopy64.exe to bin\ and rerun:
    Download: https://github.com/jschicht/RawCopy/releases
    Usage:    RawCopy64.exe /FileNamePath:C:\`$MFT /OutputPath:.\evidence\

  Option 3 - Add MFTECmd.exe to bin\ and rerun:
    Download: https://ericzimmermann.com/get-zimtools
    Usage:    MFTECmd.exe -f C:\`$MFT --csv .\mft_output\
"@ | Out-File (Join-Path $mftDir "MFT_COLLECTION_NOTE.txt") -Encoding UTF8
    }

    return $mftDir
}


# ============================================================================
# FTK IMAGER - DISK IMAGING & SLEEPING VM SUPPORT
# ============================================================================
# Calls FTK Imager CLI (ftkimager.exe) to create a forensic disk image.
# Supports both:
#   - Live volume imaging (C: drive on running machine)
#   - VMDK/VHD imaging (for the sleeping/offline VM)
#
# Image formats:
#   E01  = EnCase format (compressed, with metadata, hash verification)
#   RAW  = DD-style bit-for-bit copy
#
# For the sleeping VM: provide the full path to its .vmdk file as $SourcePath
# e.g. Get-FTKImage -SourcePath "C:\VMs\VM2\VM2.vmdk" -VmLabel "VM2_Offline"
function Get-FTKImage {
    param(
        [string]$OutputPath,
        [string]$ScriptRoot  = $PSScriptRoot,
        [string]$SourcePath  = "\\.\PhysicalDrive0",  # default: first physical disk
        [string]$VmLabel     = "disk_image",
        [string]$Format      = "E01",                  # E01 or RAW
        [string]$CaseNumber  = "",
        [string]$ExaminerName = "",
        [string]$Description = "Forensic disk image"
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === FTK Imager Disk Imaging ==="

    # Find ftkimager.exe - check script root and known subfolder
    $ftkPaths = @(
        (Join-Path $ScriptRoot "bin\ftkimager.exe"),
        (Join-Path $ScriptRoot "SimpleImager-main\ftkimager.exe"),
        (Join-Path $ScriptRoot "ftkimager.exe"),
        "C:\Users\jhg56\Documents\POWERSHELL SCRIPTING\SimpleImager-main\ftkimager.exe"
    )
    $ftk = $ftkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $ftk) {
        Write-Output "  ERROR: ftkimager.exe not found. Checked:"
        $ftkPaths | ForEach-Object { Write-Output "    $_" }
        Write-Output "  Copy ftkimager.exe (and its DLLs) into $ScriptRoot\bin\"
        return $null
    }

    Write-Output "  Using FTK Imager: $ftk"
    Write-Output "  Source          : $SourcePath"
    Write-Output "  Format          : $Format"
    Write-Output "  This may take a LONG time for full disk images (plan for 1-3+ hours)."

    $imageDir = Join-Path $OutputPath "disk_images"
    New-Item -ItemType Directory -Path $imageDir -Force | Out-Null

    $safeLabel   = ($VmLabel -replace '[^a-zA-Z0-9_-]', '_')
    $imagePrefix = Join-Path $imageDir $safeLabel
    $hashFile    = Join-Path $imageDir "${safeLabel}_hashes.txt"
    Write-Output "  Hash log will be saved to: $hashFile"

    # Build argument list
    # FTK Imager CLI syntax: ftkimager <source> <dest_prefix> [options]
    $ftkArgs = @($SourcePath, $imagePrefix)

    if ($Format -eq "E01") {
        $ftkArgs += "--e01"
        $ftkArgs += "--compress"
        $ftkArgs += "6"   # compression level 0-9; 6 is a good balance
        if ($CaseNumber)   { $ftkArgs += "--case-number"; $ftkArgs += $CaseNumber }
        if ($ExaminerName) { $ftkArgs += "--examiner";    $ftkArgs += $ExaminerName }
        if ($Description)  { $ftkArgs += "--description"; $ftkArgs += $Description }
    }

    # Always verify after acquisition (ACPO Principle 2 - do not alter evidence)
    $ftkArgs += "--verify"

    try {
        Write-Output "  Starting FTK Imager... (output below)"
        Write-Output ""
        $proc = Start-Process -FilePath $ftk -ArgumentList $ftkArgs `
                              -NoNewWindow -Wait -PassThru `
                              -RedirectStandardOutput "$imageDir\${safeLabel}_ftk_stdout.txt" `
                              -RedirectStandardError  "$imageDir\${safeLabel}_ftk_stderr.txt"

        # Show output
        if (Test-Path "$imageDir\${safeLabel}_ftk_stdout.txt") {
            Get-Content "$imageDir\${safeLabel}_ftk_stdout.txt" | ForEach-Object { Write-Output "  FTK: $_" }
        }

        if ($proc.ExitCode -eq 0) {
            $images = Get-ChildItem $imageDir -Filter "$safeLabel*" -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Extension -match '\.(E01|001|raw|img)$' }
            Write-Output ""
            Write-Output "  Imaging complete. Files created:"
            $images | ForEach-Object {
                $sizeMB = [math]::Round($_.Length / 1MB, 1)
                Write-Output "    $($_.Name) ($sizeMB MB)"
            }
            Write-Output "  Hash verification: see FTK stdout log above (look for MD5/SHA1 match)"
        } else {
            Write-Output "  WARNING: FTK Imager exited with code $($proc.ExitCode)"
            Write-Output "  Check: $imageDir\${safeLabel}_ftk_stderr.txt"
        }
    } catch {
        Write-Output "  ERROR running FTK Imager: $_"
    }

    return $imageDir
}


# ============================================================================
# SLEEPING VM WORKFLOW HELPER
# ============================================================================
# Guides the investigator through sleeping VM artefact extraction.
# Since the VM is suspended (not running), you cannot run scripts on it.
# Instead, you work with:
#   1. The .vmdk / .vhd disk image file directly
#   2. The .vmem / .vmsn memory snapshot file (if VM was suspended, not shut down)
#
# This function:
#   - Finds VMDK/VHD files on the host
#   - Images them with FTK Imager
#   - Copies the memory snapshot if present
#   - Writes notes on offline artefact extraction
function Get-SleepingVMArtefacts {
    param(
        [string]$OutputPath,
        [string]$ScriptRoot   = $PSScriptRoot,
        [string]$VmLabel      = "VM2_Sleeping",
        [string]$VmSearchPath = "C:\",         # where to look for VMDK/VHD files
        [string]$VmdkPath     = ""             # if you already know the VMDK path, set this
    )

    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] === Sleeping VM Artefact Collection ==="
    Write-Output "  NOTE: Sleeping/offline VMs must be imaged from the HOST machine."
    Write-Output ""

    $sleepDir = Join-Path $OutputPath "sleeping_vm_$VmLabel"
    New-Item -ItemType Directory -Path $sleepDir -Force | Out-Null

    # ── Find VMDK / VHD files ────────────────────────────────────────────────
    if (-not $VmdkPath) {
        Write-Output "  Searching for VMDK/VHD files under $VmSearchPath ..."
        $vmFiles = Get-ChildItem -Path $VmSearchPath -Recurse -Depth 6 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Extension -match '\.(vmdk|vhd|vhdx|ova|ovf)$' } |
                   Sort-Object Length -Descending

        if ($vmFiles) {
            Write-Output "  Found VM disk files:"
            $vmFiles | ForEach-Object {
                $sizeMB = [math]::Round($_.Length / 1MB, 1)
                Write-Output "    $($_.FullName) ($sizeMB MB)"
            }
            # Use largest VMDK (most likely the main disk, not a snapshot delta)
            $VmdkPath = ($vmFiles | Select-Object -First 1).FullName
            Write-Output ""
            Write-Output "  Automatically selected: $VmdkPath"
            Write-Output "  If this is wrong, re-run with -VmdkPath 'correct\path.vmdk'"
        } else {
            Write-Output "  WARNING: No VMDK/VHD files found under $VmSearchPath"
            Write-Output "  Set -VmSearchPath to the folder containing your VMs."
        }
    }

    # ── Look for memory snapshot (.vmem / .vmsn) ────────────────────────────
    if ($VmdkPath) {
        $vmDir = Split-Path $VmdkPath -Parent
        $memFiles = Get-ChildItem $vmDir -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(vmem|vmsn|vmss)$' }

        if ($memFiles) {
            Write-Output ""
            Write-Output "  Memory snapshot files found (VM was SUSPENDED, not shut down):"
            foreach ($mf in $memFiles) {
                $sizeMB = [math]::Round($mf.Length / 1MB, 1)
                Write-Output "    $($mf.Name) ($sizeMB MB)"
                try {
                    Copy-Item $mf.FullName $sleepDir -Force -ErrorAction Stop
                    Write-Output "    -> Copied to evidence folder"
                } catch {
                    Write-Output "    -> WARNING: Could not copy - $_"
                }
            }
            Write-Output "  Analyse .vmem with Volatility: vol.py -f vmem_file windows.pslist"
        } else {
            Write-Output "  NOTE: No memory snapshot found - VM was shut down (not suspended)."
            Write-Output "  No live memory available for this VM."
        }
    }

    # ── Image the VMDK with FTK ──────────────────────────────────────────────
    if ($VmdkPath -and (Test-Path $VmdkPath)) {
        Write-Output ""
        Write-Output "  Imaging VMDK with FTK Imager..."
        Get-FTKImage -OutputPath $sleepDir `
                     -ScriptRoot $ScriptRoot `
                     -SourcePath $VmdkPath `
                     -VmLabel $VmLabel `
                     -Format "E01" `
                     -Description "Offline VMDK image: $VmLabel"
    }

    # ── Write offline analysis notes ─────────────────────────────────────────
    @"
SLEEPING VM OFFLINE ANALYSIS NOTES
=====================================
VM Label : $VmLabel
VMDK     : $VmdkPath
Collected: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')

NEXT STEPS (offline analysis on your analyst workstation):
----------------------------------------------------------

1. MOUNT THE E01 IMAGE (read-only):
   - FTK Imager: File > Image Mounting > Mount Image (Read Only)
   - Assigned drive letter will allow browsing the file system

2. EXTRACT KEY ARTEFACTS from mounted image:
   - \Windows\System32\config\SAM       (user accounts)
   - \Windows\System32\config\SYSTEM    (USB history, timezone)
   - \Windows\System32\config\SOFTWARE  (installed programs)
   - \Windows\System32\sru\SRUDB.dat    (network usage)
   - \Windows\AppCompat\Programs\Amcache.hve (execution history)
   - \Users\*\NTUSER.DAT               (per-user artefacts)
   - \`$MFT                             (FTK Imager can export this)
   - \`$LogFile, \`$UsnJrnl:`$J          (file system journal)

3. PARSE ARTEFACTS:
   - Registry Explorer  : open .hiv / .DAT files
   - AmcacheParser.exe  : Amcache.hve -> CSV
   - MFTECmd.exe        : `$MFT -> CSV timeline
   - SrumECmd.exe       : SRUDB.dat -> network usage CSV
   - LECmd.exe          : LNK files -> CSV
   - JLECmd.exe         : Jump lists -> CSV

4. TIMELINE:
   - Use MFTECmd + log2timeline (plaso) for a super-timeline
   - Or use Eric Zimmermann's Timeline Explorer with parsed CSVs

All tools above are free from: https://ericzimmermann.com/get-zimtools
"@ | Out-File (Join-Path $sleepDir "OFFLINE_ANALYSIS_NOTES.txt") -Encoding UTF8

    Write-Output ""
    Write-Output "  Notes saved to: $sleepDir\OFFLINE_ANALYSIS_NOTES.txt"
    Write-Output "  Evidence saved to: $sleepDir"

    return $sleepDir
}
