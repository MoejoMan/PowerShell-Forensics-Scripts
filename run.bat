@echo off
REM Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~0\" %*' -Verb RunAs"
    exit /b
)

REM If we get here, we're running as admin
echo.
echo =====================================================
echo   Digital Forensics Data Collection Script
echo =====================================================
echo.
echo Running with Administrator privileges...
echo Script location: %~dp0
echo.

REM Change to script directory
cd /d "%~dp0"

REM Build argument string from batch params (supports -VmLabel, -SkipRamDump, -SkipHashes)
set "PS_ARGS="
:parse
if "%~1"=="" goto :run
set "PS_ARGS=%PS_ARGS% %1"
shift
goto :parse

:run
REM Run the PowerShell script
echo Starting data collection...
powershell.exe -ExecutionPolicy Bypass -File "main.ps1" %PS_ARGS%

REM Keep window open so user can see results
echo.
echo =====================================================
echo Data collection completed!
echo Check the Evidence folder for collected data
echo Check the Transcript folder for execution logs
echo =====================================================
pause
