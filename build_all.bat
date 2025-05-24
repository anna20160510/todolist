@echo off
cd /d "%~dp0"
echo [Info] Running Python build script...
python build_all.py

IF %ERRORLEVEL% NEQ 0 (
    echo [Error] Build failed. See build_log.txt for details.
    pause
    exit /b 1
)

echo [Success] Build completed. Check the dist\ folder.
pause
