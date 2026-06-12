"""AiCSO 离线安装脚本
在内网机器上运行，从离线包安装所有依赖
前提：Python 3.11+ 已安装
"""
import os
import subprocess
import sys
from pathlib import Path


def find_offline_dir():
    """查找offline_pkgs目录"""
    # 检查当前目录
    cwd = Path.cwd()
    candidates = [
        cwd / "offline_pkgs",
        cwd / "offline_dist" / "offline_pkgs",
        Path(__file__).parent.parent / "offline_pkgs",
        Path(__file__).parent.parent / "offline_dist" / "offline_pkgs",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def find_project_root():
    """查找项目根目录"""
    cwd = Path.cwd()
    candidates = [
        cwd / "offline_dist",
        cwd,
        Path(__file__).parent.parent,
    ]
    for p in candidates:
        if (p / "pyproject.toml").exists():
            return p
    return None


def run(cmd, **kwargs):
    print(f"  > {cmd}")
    result = subprocess.run(cmd, shell=True, **kwargs)
    return result.returncode == 0


def main():
    print("=" * 50)
    print("AiCSO Offline Installer")
    print("=" * 50)

    # 查找离线包目录
    print("\n[1/4] Locating offline packages...")
    offline_dir = find_offline_dir()
    if not offline_dir:
        print("ERROR: Cannot find offline_pkgs directory!")
        print("Make sure you have extracted aicso-offline.tar first.")
        sys.exit(1)
    print(f"  Found: {offline_dir}")

    pkg_count = len(list(offline_dir.glob("*.whl"))) + len(list(offline_dir.glob("*.tar.gz")))
    print(f"  Packages: {pkg_count}")

    # 查找项目根目录
    project_root = find_project_root()
    if not project_root:
        print("ERROR: Cannot find pyproject.toml!")
        sys.exit(1)
    print(f"  Project root: {project_root}")

    # 安装依赖
    print("\n[2/4] Installing dependencies from offline packages...")
    req_file = project_root / "requirements.txt"
    if req_file.exists():
        ok = run(f'pip install --no-index --find-links="{offline_dir}" -r "{req_file}"')
        if not ok:
            print("  Batch install failed, trying one by one...")
            for line in req_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    run(f'pip install --no-index --find-links="{offline_dir}" "{line}"')
    else:
        print("  No requirements.txt found, skipping dependency install")

    # 安装项目本身
    print("\n[3/4] Installing AiCSO...")
    run(f'pip install --no-index --find-links="{offline_dir}" -e "{project_root}"')

    # 初始化
    print("\n[4/4] Initializing database...")
    init_script = project_root / "scripts" / "init_db.py"
    if init_script.exists():
        run(f'python "{init_script}"')

    print()
    print("=" * 50)
    print("AiCSO installed successfully!")
    print()
    print("Quick start:")
    print("  aicso init")
    print("  aicso datasource types")
    print("  aicso datasource list")
    print("  aicso case create --title 'Test' --severity medium")
    print("  aicso case list")
    print("=" * 50)


if __name__ == "__main__":
    main()
