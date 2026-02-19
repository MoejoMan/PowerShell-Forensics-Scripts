@echo off
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
echo   1. Single VM collection  (you provide a label)
echo   2. Multi-VM batch mode   (loops over multiple VMs)
echo.
set /p MODE="Select mode (1 or 2): "

cd /d "%~dp0"

if "%MODE%"=="2" (
    echo.
    echo Starting Multi-VM Batch Mode...
    echo You will be prompted for each VM label and options.
    echo.
    powershell.exe -ExecutionPolicy Bypass -File "main.ps1" -BatchMode
) else (
    set /p LABEL="Enter VM label (e.g. VM1_Live): "
    set /p SKIPRAM="Skip RAM dump? (Y/N): "
    set "PS_ARGS=-VmLabel %LABEL%"
    if /i "%SKIPRAM%"=="Y" set "PS_ARGS=%PS_ARGS% -SkipRamDump"
    echo.
    echo Starting collection for: %LABEL%
    powershell.exe -ExecutionPolicy Bypass -File "main.ps1" %PS_ARGS%
)

echo.
echo =====================================================
echo  Done! Check Evidence and HTMLReport folders.
echo =====================================================
pause
