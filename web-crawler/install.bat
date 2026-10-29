@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [1/2] Installing packages...
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo [2/2] Installing Chromium browser (large download, one time)...
python -m playwright install chromium
if errorlevel 1 goto fail
echo.
echo Done. Run "run.bat" to start.
pause
exit /b 0
:fail
echo.
echo Install failed. Check Python (3.10+, PATH) and internet access.
pause
exit /b 1
