#!/bin/bash
# ============================================
# AiCSO 离线打包脚本 (Linux/Mac)
# 在有网络的机器上运行，打包所有依赖为wheel文件
# ============================================

set -e

echo "[1/3] Creating offline packages directory..."
mkdir -p offline_pkgs

echo "[2/3] Downloading all dependencies as wheels..."
pip download -r requirements.txt -d offline_pkgs --only-binary=:all: --python-version 3.11 --platform manylinux2014_x86_64
pip download -r requirements.txt -d offline_pkgs --no-binary=:none:

echo "[3/3] Creating offline archive..."
tar -cf aicso-offline.tar offline_pkgs/ requirements.txt pyproject.toml src/ config.yaml playbooks/ skills/ scripts/

echo ""
echo "============================================"
echo "Offline package created: aicso-offline.tar"
echo "Transfer this file to the internal network."
echo "============================================"
