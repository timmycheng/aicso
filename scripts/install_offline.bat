@echo off
REM ============================================
REM AiCSO 离线安装脚本
REM 在内网机器上运行，从离线包安装
REM 前提：Python 3.11+ 已安装
REM ============================================

echo ============================================
echo AiCSO Offline Installer
echo ============================================
echo.

echo [1/4] Extracting offline package...
if exist "aicso-offline.tar" (
    tar -xf aicso-offline.tar
    cd offline_dist
) else if exist "offline_pkgs" (
    echo Found offline_pkgs directory, using current directory.
) else (
    echo ERROR: Cannot find aicso-offline.tar or offline_pkgs directory!
    echo Please run this script from the directory containing the offline package.
    pause
    exit /b 1
)

echo [2/4] Installing dependencies from offline packages...
pip install --no-index --find-links=offline_pkgs -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: Some packages failed. Trying one by one...
    for /f "tokens=*" %%p in (requirements.txt) do (
        echo Installing: %%p
        pip install --no-index --find-links=offline_pkgs "%%p" 2>nul
    )
)

echo [3/4] Installing AiCSO...
pip install --no-index --find-links=offline_pkgs -e .

echo [4/4] Initializing...
python scripts\init_db.py

echo.
echo ============================================
echo AiCSO installed successfully!
echo.
echo Quick start:
echo   aicso init
echo   aicso datasource types
echo   aicso datasource list
echo   aicso case create --title "Test" --severity medium
echo   aicso case list
echo ============================================
pause
