@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  Forensic Data Collection - Launch Script
REM  Joseph Hayes | Digital Forensics Assessment
REM ============================================================

REM Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~0\" %*' -Verb RunAs"
    exit /b
)

echo.
echo =====================================================
echo   Digital Forensics Data Collection
echo =====================================================
echo.
echo   CORRECT ORDER OF OPERATIONS:
echo     Step 1: Option 3 from the HOST  (image VMDKs first)
echo     Step 2: Resume sleeping VM, set up shared folder
echo     Step 3: Option 1 from INSIDE the VM  (live triage)
echo.
echo   1. Live triage inside VM    (run INSIDE the resumed VM)
echo   2. Multi-VM batch mode      (loops over multiple VMs)
echo   3. Image VMs from host      (do this FIRST, before resuming)
echo.
set /p MODE="Select mode (1, 2, or 3): "

cd /d "%~dp0"

if "!MODE!"=="3" (
    echo.
    echo =====================================================
    echo   HOST-FIRST: Imaging VMs before resuming
    echo =====================================================
    echo.
    echo   This will image VMDK files and copy .vmem snapshots.
    echo   No VMs will be booted or resumed.
    echo.
    powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -ImageFirst
    goto :done
)

if "!MODE!"=="2" (
    echo.
    echo Starting Multi-VM Batch Mode...
    echo You will be prompted for each VM label and options.
    echo.
    powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -BatchMode
    goto :done
)

set /p LABEL="Enter VM label (e.g. VM1_Live): "
set /p SKIPRAM="Skip RAM dump? (Y/N): "
set "PS_ARGS=-VmLabel !LABEL!"
if /i "!SKIPRAM!"=="Y" set "PS_ARGS=!PS_ARGS! -SkipRamDump"
echo.
echo Starting collection for: !LABEL!
powershell.exe -ExecutionPolicy Bypass -File "main.ps1" !PS_ARGS!

:done

echo.
echo =====================================================
echo  Done! Check Evidence and HTMLReport folders.
echo =====================================================
pause
