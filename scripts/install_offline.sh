#!/bin/bash
# ============================================
# AiCSO 离线安装脚本 (Linux/Mac)
# 在内网机器上运行，从离线包安装
# ============================================

set -e

echo "[1/4] Extracting offline package..."
if [ -f "aicso-offline.tar" ]; then
    tar -xf aicso-offline.tar
elif [ -d "offline_pkgs" ]; then
    echo "offline_pkgs directory found, skipping extraction."
else
    echo "ERROR: Cannot find aicso-offline.tar or offline_pkgs directory!"
    exit 1
fi

echo "[2/4] Installing dependencies from offline packages..."
pip install --no-index --find-links=offline_pkgs -r requirements.txt

echo "[3/4] Installing AiCSO in development mode..."
pip install --no-index --find-links=offline_pkgs -e .

echo "[4/4] Initializing database..."
python scripts/init_db.py

echo ""
echo "============================================"
echo "AiCSO installed successfully!"
echo ""
echo "Quick start:"
echo "  aicso init"
echo "  aicso case create --title 'Test' --severity medium"
echo "  aicso case list"
echo "  aicso datasource types"
echo "============================================"
