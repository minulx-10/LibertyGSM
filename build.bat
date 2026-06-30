@echo off
echo ==========================================
echo  LibertyGSM Executable Builder
echo ==========================================
echo.

:: Check for python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python and try again.
    pause
    exit /b 1
)

echo [1/3] Installing dependencies (pydivert, PyInstaller)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo.
echo [2/3] Building executable using PyInstaller...
:: LibertyGSM.spec bundles WinDivert, requests Administrator, and excludes
:: test-only/optional packages from the release binary.
python -m PyInstaller --clean LibertyGSM.spec

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed. Please check the logs above.
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo ==========================================
echo  Build complete!
echo  Your executable is located at:
echo  dist\LibertyGSM.exe
echo  ^(Run it as Administrator -- it will prompt automatically.^)
echo ==========================================
echo.
pause
