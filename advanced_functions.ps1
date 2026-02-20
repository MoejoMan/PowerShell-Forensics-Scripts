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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Registry Hives ==="

    $hivesDir = Join-Path $OutputPath "registry_hives"
    New-Item -ItemType Directory -Path $hivesDir -Force | Out-Null

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "WARNING: Not running as administrator. SAM and SECURITY hives will likely fail."
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
                Write-Host "  Saved $($hive.Key).hiv ($sizeMB MB)"
            } else {
                Write-Host "  WARNING: $($hive.Key) - reg save reported: $output"
            }
        } catch {
            Write-Host "  ERROR saving $($hive.Key): $_"
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
                Write-Host "  Copied NTUSER.DAT for $($prof.Name) ($sizeMB MB)"
            } catch {
                # File is locked - use Volume Shadow Copy trick or reg save
                try {
                    $regPath = "HKU\$($prof.Name)_TEMP"
                    & reg load $regPath $ntuserSrc 2>&1 | Out-Null
                    if (Test-Path $ntuserDst) { Remove-Item $ntuserDst -Force }
                    & reg save $regPath $ntuserDst /y 2>&1 | Out-Null
                    & reg unload $regPath 2>&1 | Out-Null
                    if (Test-Path $ntuserDst) {
                        Write-Host "  Saved NTUSER.DAT for $($prof.Name) via reg load/save"
                    } else {
                        Write-Host "  WARNING: Could not export NTUSER.DAT for $($prof.Name) (file locked)"
                    }
                } catch {
                    Write-Host "  WARNING: NTUSER.DAT locked for $($prof.Name) - collect via VSS or offline"
                }
            }
        }

        # UsrClass.dat
        $usrClassSrc = Join-Path $prof.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
        $usrClassDst = Join-Path $hivesDir "UsrClass_$($prof.Name).dat"
        if (Test-Path $usrClassSrc) {
            try {
                Copy-Item $usrClassSrc $usrClassDst -Force -ErrorAction Stop
                Write-Host "  Copied UsrClass.dat for $($prof.Name)"
            } catch {
                Write-Host "  WARNING: UsrClass.dat locked for $($prof.Name)"
            }
        }
    }

    Write-Host "  Registry hives saved to: $hivesDir"
    Write-Host "  TIP: Load .hiv files in Registry Explorer (Eric Zimmermann) for full analysis."
    Write-Host "  TIP: Run RegRipper against NTUSER.DAT for automated artefact extraction."

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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting SRUM Database ==="

    $srumSrc = "C:\Windows\System32\sru\SRUDB.dat"
    $srumDst = Join-Path $OutputPath "SRUDB.dat"

    if (-not (Test-Path $srumSrc)) {
        Write-Host "  (SRUM database not found at $srumSrc)"
        return $null
    }

    try {
        Copy-Item $srumSrc $srumDst -Force -ErrorAction Stop
        $sizeMB = [math]::Round((Get-Item $srumDst).Length / 1MB, 2)
        Write-Host "  SRUM database copied ($sizeMB MB) -> $srumDst"
        Write-Host "  Parse with: SrumECmd.exe -f `"$srumDst`" --csv output_folder"
    } catch {
        # File is locked by svchost - try esentutl, then VSS, then shadow copy
        Write-Host "  WARNING: SRUDB.dat is locked. Trying esentutl.exe /y /vss..."
        $srumCopied = $false
        try {
            $esentResult = & esentutl.exe /y /vss $srumSrc /d $srumDst 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path $srumDst)) {
                $sizeMB = [math]::Round((Get-Item $srumDst).Length / 1MB, 2)
                Write-Host "  SRUM database copied via esentutl ($sizeMB MB) -> $srumDst"
                $srumCopied = $true
            }
        } catch {
            Write-Host "  esentutl failed - trying shadow copy..."
        }

        if (-not $srumCopied) {
            try {
                $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
                if ($shadows) {
                    $shadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
                    $shadowPath = $shadow.DeviceName + "\Windows\System32\sru\SRUDB.dat"
                    Copy-Item $shadowPath $srumDst -Force -ErrorAction Stop
                    Write-Host "  SRUM database copied from shadow copy -> $srumDst"
                    $srumCopied = $true
                } else {
                    Write-Host "  No shadow copies available."
                }
            } catch {
                Write-Host "  Shadow copy failed - $_"
            }
        }

        if (-not $srumCopied) {
            Write-Host "  ERROR: All SRUDB.dat copy methods failed."
            Write-Host "  Will attempt collection from offline image analysis."
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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Amcache & ShimCache ==="

    $amcacheDir = Join-Path $OutputPath "amcache"
    New-Item -ItemType Directory -Path $amcacheDir -Force | Out-Null

    $amcacheSrc = "C:\Windows\AppCompat\Programs\Amcache.hve"
    $amcacheDst = Join-Path $amcacheDir "Amcache.hve"

    if (Test-Path $amcacheSrc) {
        $amcacheCopied = $false
        try {
            Copy-Item $amcacheSrc $amcacheDst -Force -ErrorAction Stop
            $sizeMB = [math]::Round((Get-Item $amcacheDst).Length / 1MB, 2)
            Write-Host "  Amcache.hve copied ($sizeMB MB) -> $amcacheDst"
            Write-Host "  Parse with: AmcacheParser.exe -f `"$amcacheDst`" --csv output_folder"
            $amcacheCopied = $true
        } catch {
            Write-Host "  WARNING: Amcache.hve locked - trying esentutl.exe /y /vss..."
            try {
                $esentResult = & esentutl.exe /y /vss $amcacheSrc /d $amcacheDst 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $amcacheDst)) {
                    $sizeMB = [math]::Round((Get-Item $amcacheDst).Length / 1MB, 2)
                    Write-Host "  Amcache.hve copied via esentutl ($sizeMB MB) -> $amcacheDst"
                    $amcacheCopied = $true
                }
            } catch {
                Write-Host "  esentutl failed - trying shadow copy..."
            }

            if (-not $amcacheCopied) {
                try {
                    $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
                    if ($shadows) {
                        $shadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
                        $shadowPath = $shadow.DeviceName + "\Windows\AppCompat\Programs\Amcache.hve"
                        Copy-Item $shadowPath $amcacheDst -Force -ErrorAction Stop
                        Write-Host "  Amcache.hve copied from shadow copy"
                        $amcacheCopied = $true
                    } else {
                        Write-Host "  No shadow copies available"
                    }
                } catch {
                    Write-Host "  ERROR: All Amcache.hve copy methods failed - $_"
                }
            }
        }
    } else {
        Write-Host "  (Amcache.hve not found - may be older Windows version)"
    }

    # ShimCache lives in SYSTEM hive - export just that key as a readable dump
    Write-Host "  Extracting ShimCache entries from registry..."
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
                Write-Host "  ShimCache raw data found ($sizeBytes bytes) - saved in SYSTEM.hiv"
                Write-Host "  Parse with: AppCompatCacheParser.exe -f SYSTEM.hiv --csv output_folder"
            }
        }
    } catch {
        Write-Host "  WARNING: ShimCache read failed - $_"
    }
    # Export ShimCache metadata if any entries found
    if ($shimItems.Count -gt 0) {
        $shimItems | Export-Csv (Join-Path $amcacheDir 'shimcache_metadata.csv') -NoTypeInformation -Encoding UTF8
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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting LNK Files & Jump Lists ==="

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
                Write-Host "  Copied $($lnkFiles.Count) LNK files for $($prof.Name)"
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
                    Write-Host "  Copied $($jlFiles.Count) $jlFolder files for $($prof.Name)"
                }
            }
        }
    }

    if ($items.Count -gt 0) {
        $items | Export-Csv (Join-Path $OutputPath "lnk_metadata.csv") -NoTypeInformation -Encoding UTF8
        Write-Host "  LNK metadata CSV: $($items.Count) entries -> $OutputPath\lnk_metadata.csv"
    }

    Write-Host "  Raw LNK/JumpList files saved to: $lnkDir"
    Write-Host "  Parse with: LECmd.exe -d `"$lnkDir`" --csv output_folder"
    Write-Host "  Parse with: JLECmd.exe -d `"$lnkDir`" --csv output_folder"

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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting Thumbnail Cache ==="

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
                    Write-Host "  WARNING: Could not copy $($f.Name) for $($prof.Name) - $_"
                }
            }
            if ($thumbFiles) {
                Write-Host "  Copied $($thumbFiles.Count) thumbcache files for $($prof.Name)"
            }
        }
    }

    if ($copied -gt 0) {
        Write-Host "  $copied thumbcache files saved to: $thumbDir"
        Write-Host "  Parse with: Thumbcache Viewer - https://thumbcacheviewer.github.io"
    } else {
        Write-Host "  (No thumbnail cache files found)"
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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Collecting MFT & USN Journal ==="

    $mftDir = Join-Path $OutputPath "mft_usn"
    New-Item -ItemType Directory -Path $mftDir -Force | Out-Null

    # â”€â”€ 1. USN Journal via fsutil (no extra tools needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Write-Host "  Exporting USN Journal via fsutil..."
    try {
        $usnOut = Join-Path $mftDir "usn_journal.csv"
        $usnRaw = & fsutil usn readjournal C: csv 2>&1
        if ($usnRaw -and $LASTEXITCODE -eq 0) {
            $usnRaw | Out-File $usnOut -Encoding UTF8
            Write-Host "  USN Journal exported -> $usnOut"
        } else {
            Write-Host "  WARNING: fsutil usn failed - $usnRaw"
        }
    } catch {
        Write-Host "  WARNING: USN Journal export failed - $_"
    }

    # ── 2. $MFT extraction ── PowerForensics > RawCopy > MFTECmd > esentutl ────
    # Try PowerForensics Copy-ForensicFile first (reads raw NTFS, no external exe needed)
    $pfModule = Join-Path $ScriptRoot "bin\PowerForensicsv2\PowerForensicsv2.psd1"
    $hasPowerForensics = Test-Path $pfModule

    $mftEcmdPaths = @(
        (Join-Path $ScriptRoot "bin\MFTECmd.exe"),
        (Join-Path $ScriptRoot "bin\MFTECmd\MFTECmd.exe")
    )
    $mftEcmd = $mftEcmdPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    $mftExtracted = $false

    # Strategy A: PowerForensics Copy-ForensicFile (reads raw NTFS directly)
    if ($hasPowerForensics -and -not $mftExtracted) {
        Write-Host "  PowerForensics found — extracting `$MFT via Copy-ForensicFile..."
        try {
            Import-Module $pfModule -Force -ErrorAction Stop
            $mftDest = Join-Path $mftDir "`$MFT"
            Copy-ForensicFile -Path "C:\`$MFT" -Destination $mftDest -ErrorAction Stop
            if (Test-Path $mftDest) {
                $sizeMB = [math]::Round((Get-Item $mftDest).Length / 1MB, 1)
                Write-Host "  `$MFT extracted via PowerForensics ($sizeMB MB) -> $mftDest"
                $mftExtracted = $true
            }
        } catch {
            Write-Host "  PowerForensics Copy-ForensicFile failed: $_"
        }
    }

    if (-not $mftExtracted -and $mftEcmd) {
        Write-Host "  MFTECmd found - parsing `$MFT directly..."
        try {
            $mftCsvOut = Join-Path $mftDir "mft_parsed"
            New-Item -ItemType Directory -Path $mftCsvOut -Force | Out-Null
            & $mftEcmd -f C:\`$MFT --csv $mftCsvOut 2>&1 | ForEach-Object { Write-Host "  $_" }
            Write-Host "  `$MFT parsed -> $mftCsvOut"
            $mftExtracted = $true
        } catch {
            Write-Host "  ERROR: MFTECmd failed - $_"
        }
    }

    # â”€â”€ Fallback: esentutl.exe /y /vss (built-in Windows, no external tools) â”€â”€
    if (-not $mftExtracted) {
        Write-Host "  No external tools found. Trying esentutl.exe /y /vss (built-in Windows)..."
        try {
            $mftDest = Join-Path $mftDir "`$MFT"
            $esentResult = & esentutl.exe /y /vss "C:\`$MFT" /d $mftDest 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path $mftDest)) {
                $sizeMB = [math]::Round((Get-Item $mftDest).Length / 1MB, 1)
                Write-Host "  `$MFT extracted via esentutl ($sizeMB MB) -> $mftDest"
                $mftExtracted = $true
            } else {
                Write-Host "  esentutl.exe failed: $esentResult"
            }
        } catch {
            Write-Host "  esentutl.exe error: $_"
        }
    }

    if (-not $mftExtracted) {
        Write-Host "  WARNING: All `$MFT extraction methods failed."
        Write-Host "  The raw `$MFT file is locked by NTFS. Last resort: FTK Imager GUI."
    }

    # ── 3. $LogFile (NTFS transaction log) ─────────────────────────────────────
    # The NTFS $LogFile records all metadata changes (file create/delete/rename).
    # Critical for timeline reconstruction — shows what happened even after deletion.
    Write-Host "  Extracting `$LogFile (NTFS transaction log)..."
    $logFileExtracted = $false

    # Strategy A: PowerForensics
    if ($hasPowerForensics -and -not $logFileExtracted) {
        try {
            Import-Module $pfModule -Force -ErrorAction Stop
            $logDest = Join-Path $mftDir "`$LogFile"
            Copy-ForensicFile -Path "C:\`$LogFile" -Destination $logDest -ErrorAction Stop
            if (Test-Path $logDest) {
                $sizeMB = [math]::Round((Get-Item $logDest).Length / 1MB, 1)
                Write-Host "  `$LogFile extracted via PowerForensics ($sizeMB MB) -> $logDest"
                $logFileExtracted = $true
            }
        } catch {
            Write-Host "  PowerForensics `$LogFile failed: $_"
        }
    }

    # Strategy B: esentutl fallback
    if (-not $logFileExtracted) {
        try {
            $logDest = Join-Path $mftDir "`$LogFile"
            $esentLog = & esentutl.exe /y /vss "C:\`$LogFile" /d $logDest 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path $logDest)) {
                $sizeMB = [math]::Round((Get-Item $logDest).Length / 1MB, 1)
                Write-Host "  `$LogFile extracted via esentutl ($sizeMB MB) -> $logDest"
                $logFileExtracted = $true
            } else {
                Write-Host "  esentutl `$LogFile failed: $esentLog"
            }
        } catch {
            Write-Host "  esentutl `$LogFile error: $_"
        }
    }

    if (-not $logFileExtracted) {
        Write-Host "  WARNING: Could not extract `$LogFile."
    }

    # ── 4. $UsnJrnl:$J raw binary copy ────────────────────────────────────────
    # The raw $J stream is needed by MFTECmd for proper parsing.
    # fsutil gives a text dump (already done above); this copies the binary stream.
    Write-Host "  Extracting `$UsnJrnl:`$J (raw binary stream)..."
    $usnExtracted = $false

    # Strategy A: PowerForensics
    if ($hasPowerForensics -and -not $usnExtracted) {
        try {
            Import-Module $pfModule -Force -ErrorAction Stop
            $usnDest = Join-Path $mftDir "`$J"
            Copy-ForensicFile -Path "C:\`$Extend\`$UsnJrnl" -Destination $usnDest -ErrorAction Stop
            if (Test-Path $usnDest) {
                $sizeMB = [math]::Round((Get-Item $usnDest).Length / 1MB, 1)
                Write-Host "  `$UsnJrnl:`$J extracted via PowerForensics ($sizeMB MB) -> $usnDest"
                $usnExtracted = $true
            }
        } catch {
            Write-Host "  PowerForensics `$UsnJrnl:`$J failed: $_"
        }
    }

    # Strategy B: esentutl fallback
    if (-not $usnExtracted) {
        try {
            $usnDest = Join-Path $mftDir "`$J"
            $esentUsn = & esentutl.exe /y /vss "C:\`$Extend\`$UsnJrnl:`$J" /d $usnDest 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path $usnDest)) {
                $sizeMB = [math]::Round((Get-Item $usnDest).Length / 1MB, 1)
                Write-Host "  `$UsnJrnl:`$J extracted via esentutl ($sizeMB MB) -> $usnDest"
                $usnExtracted = $true
            } else {
                Write-Host "  esentutl `$UsnJrnl:`$J failed: $esentUsn"
            }
        } catch {
            Write-Host "  esentutl `$UsnJrnl:`$J error: $_"
        }
    }

    if (-not $usnExtracted) {
        Write-Host "  WARNING: Could not extract raw `$UsnJrnl:`$J. The text dump from fsutil is still available."
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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === FTK Imager Disk Imaging ==="

    # Find ftkimager.exe - check bin\FTKImager\ and fallbacks
    $ftkPaths = @(
        (Join-Path $ScriptRoot "bin\FTKImager\ftkimager.exe"),
        (Join-Path $ScriptRoot "bin\ftkimager.exe"),
        (Join-Path $ScriptRoot "SimpleImager-main\ftkimager.exe"),
        (Join-Path $ScriptRoot "ftkimager.exe")
    )
    $ftk = $ftkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $ftk) {
        Write-Host "  ERROR: ftkimager.exe not found. Checked:"
        $ftkPaths | ForEach-Object { Write-Host "    $_" }
        Write-Host "  Copy ftkimager.exe (and its DLLs) into $ScriptRoot\bin\"
        return $null
    }

    Write-Host "  Using FTK Imager: $ftk"
    Write-Host "  Source          : $SourcePath"
    Write-Host "  Format          : $Format"
    Write-Host "  This may take a LONG time for full disk images (plan for 1-3+ hours)."

    $imageDir = Join-Path $OutputPath "disk_images"
    New-Item -ItemType Directory -Path $imageDir -Force | Out-Null

    $safeLabel   = ($VmLabel -replace '[^a-zA-Z0-9_-]', '_')
    $imagePrefix = Join-Path $imageDir $safeLabel
    $hashFile    = Join-Path $imageDir "${safeLabel}_hashes.txt"
    Write-Host "  Hash log will be saved to: $hashFile"

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
        Write-Host "  Starting FTK Imager... (output below)"
        Write-Host ""
        $proc = Start-Process -FilePath $ftk -ArgumentList $ftkArgs `
                              -NoNewWindow -Wait -PassThru `
                              -RedirectStandardOutput "$imageDir\${safeLabel}_ftk_stdout.txt" `
                              -RedirectStandardError  "$imageDir\${safeLabel}_ftk_stderr.txt"

        # Show output
        if (Test-Path "$imageDir\${safeLabel}_ftk_stdout.txt") {
            Get-Content "$imageDir\${safeLabel}_ftk_stdout.txt" | ForEach-Object { Write-Host "  FTK: $_" }
        }

        if ($proc.ExitCode -eq 0) {
            $images = Get-ChildItem $imageDir -Filter "$safeLabel*" -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Extension -match '\.(E01|001|raw|img)$' }
            Write-Host ""
            Write-Host "  Imaging complete. Files created:"
            $images | ForEach-Object {
                $sizeMB = [math]::Round($_.Length / 1MB, 1)
                Write-Host "    $($_.Name) ($sizeMB MB)"
            }
            Write-Host "  Hash verification: see FTK stdout log above (look for MD5/SHA1 match)"
        } else {
            Write-Host "  WARNING: FTK Imager exited with code $($proc.ExitCode)"
            Write-Host "  Check: $imageDir\${safeLabel}_ftk_stderr.txt"
        }
    } catch {
        Write-Host "  ERROR running FTK Imager: $_"
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

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Sleeping VM Artefact Collection ==="
    Write-Host "  NOTE: Sleeping/offline VMs must be imaged from the HOST machine."
    Write-Host ""

    $sleepDir = Join-Path $OutputPath "sleeping_vm_$VmLabel"
    New-Item -ItemType Directory -Path $sleepDir -Force | Out-Null

    # â”€â”€ Find VMDK / VHD files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (-not $VmdkPath) {
        Write-Host "  Searching for VMDK/VHD files under $VmSearchPath ..."
        $vmFiles = Get-ChildItem -Path $VmSearchPath -Recurse -Depth 6 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Extension -match '\.(vmdk|vhd|vhdx|ova|ovf)$' } |
                   Sort-Object Length -Descending

        if ($vmFiles) {
            Write-Host "  Found VM disk files:"
            $vmFiles | ForEach-Object {
                $sizeMB = [math]::Round($_.Length / 1MB, 1)
                Write-Host "    $($_.FullName) ($sizeMB MB)"
            }
            # Use largest VMDK (most likely the main disk, not a snapshot delta)
            $VmdkPath = ($vmFiles | Select-Object -First 1).FullName
            Write-Host ""
            Write-Host "  Automatically selected: $VmdkPath"
            Write-Host "  If this is wrong, re-run with -VmdkPath 'correct\path.vmdk'"
        } else {
            Write-Host "  WARNING: No VMDK/VHD files found under $VmSearchPath"
            Write-Host "  Set -VmSearchPath to the folder containing your VMs."
        }
    }

    # â”€â”€ Look for memory snapshot (.vmem / .vmsn) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if ($VmdkPath) {
        $vmDir = Split-Path $VmdkPath -Parent
        $memFiles = Get-ChildItem $vmDir -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(vmem|vmsn|vmss)$' }

        if ($memFiles) {
            Write-Host ""
            Write-Host "  Memory snapshot files found (VM was SUSPENDED, not shut down):"
            foreach ($mf in $memFiles) {
                $sizeMB = [math]::Round($mf.Length / 1MB, 1)
                Write-Host "    $($mf.Name) ($sizeMB MB)"
                try {
                    Copy-Item $mf.FullName $sleepDir -Force -ErrorAction Stop
                    Write-Host "    -> Copied to evidence folder"
                } catch {
                    Write-Host "    -> WARNING: Could not copy - $_"
                }
            }
            Write-Host "  Analyse .vmem with Volatility: vol.py -f vmem_file windows.pslist"
        } else {
            Write-Host "  NOTE: No memory snapshot found - VM was shut down (not suspended)."
            Write-Host "  No live memory available for this VM."
        }
    }

    # â”€â”€ Image the VMDK with FTK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if ($VmdkPath -and (Test-Path $VmdkPath)) {
        Write-Host ""
        Write-Host "  Imaging VMDK with FTK Imager..."
        Get-FTKImage -OutputPath $sleepDir `
                     -ScriptRoot $ScriptRoot `
                     -SourcePath $VmdkPath `
                     -VmLabel $VmLabel `
                     -Format "E01" `
                     -Description "Offline VMDK image: $VmLabel"
    }

    # â”€â”€ Write offline analysis notes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    Write-Host ""
    Write-Host "  Notes saved to: $sleepDir\OFFLINE_ANALYSIS_NOTES.txt"
    Write-Host "  Evidence saved to: $sleepDir"

    return $sleepDir
}
