@echo off
REM ============================================
REM AiCSO 离线打包脚本
REM 在有网络的机器上运行，打包所有依赖为wheel文件
REM ============================================

echo [1/4] Creating offline packages directory...
if not exist "offline_pkgs" mkdir offline_pkgs

echo [2/4] Downloading dependencies (this may take a few minutes)...
REM 下载Windows平台的wheel
pip download -r requirements.txt -d offline_pkgs --only-binary=:all: --platform win_amd64 --python-version 3.11 2>nul
REM 下载通用wheel（无平台限制）
pip download -r requirements.txt -d offline_pkgs --only-binary=:all: 2>nul
REM 下载纯源码包（如有）
pip download -r requirements.txt -d offline_pkgs --no-binary=:none: 2>nul

echo [3/4] Copying project files...
if not exist "offline_dist" mkdir offline_dist
xcopy /E /I /Y src offline_dist\src
xcopy /E /I /Y playbooks offline_dist\playbooks
xcopy /E /I /Y skills offline_dist\skills
xcopy /E /I /Y scripts offline_dist\scripts
copy /Y pyproject.toml offline_dist\
copy /Y requirements.txt offline_dist\
copy /Y config.yaml offline_dist\
copy /Y README.md offline_dist\
copy /Y LICENSE offline_dist\
xcopy /E /I /Y offline_pkgs offline_dist\offline_pkgs

echo [4/4] Creating offline archive...
tar -cf aicso-offline.tar offline_dist

echo.
echo ============================================
echo Offline package created: aicso-offline.tar
echo Size:
dir /b aicso-offline.tar
echo.
echo Transfer this file to the internal network machine.
echo Then run: scripts\install_offline.bat
echo ============================================
pause
