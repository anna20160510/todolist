@echo off
cd /d "%~dp0"
echo [Info] Running Python build script...
python build_all.py

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Python build script failed.
    echo         See build_log.txt for more details.
    pause
    exit /b 1
)

REM Check if the .exe file was created
IF EXIST "dist\ui.exe" (
    echo.
    echo [SUCCESS] Build completed successfully!
    echo          Your executable is here: dist\ui.exe
) ELSE (
    echo.
    echo [WARNING] The executable was NOT created.
    echo           This likely means PyInstaller is not installed.
    echo           Run: pip install pyinstaller
)

echo.
pause
