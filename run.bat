@echo off
REM Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~0\"' -Verb RunAs"
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

REM Run the PowerShell script
echo Starting data collection...
powershell.exe -ExecutionPolicy Bypass -File "main.ps1"

REM Keep window open so user can see results
echo.
echo =====================================================
echo Data collection completed!
echo Check the Evidence folder for collected data
echo Check the Transcript folder for execution logs
echo =====================================================
pause
