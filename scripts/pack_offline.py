"""AiCSO 离线打包脚本
在有网络的机器上运行，打包所有依赖为wheel文件
"""
import os
import subprocess
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).parent.parent
OFFLINE_DIR = ROOT / "offline_pkgs"
DIST_DIR = ROOT / "offline_dist"
ARCHIVE = ROOT / "aicso-offline.tar"


def run(cmd, **kwargs):
    print(f"  > {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=ROOT, **kwargs)
    return result.returncode == 0


def main():
    print("=" * 50)
    print("AiCSO Offline Packager")
    print("=" * 50)

    # Step 1: 创建目录
    print("\n[1/5] Preparing directories...")
    OFFLINE_DIR.mkdir(exist_ok=True)
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir()

    # Step 2: 下载依赖wheel
    print("\n[2/5] Downloading dependencies as wheels...")
    req_file = ROOT / "requirements.txt"
    if not req_file.exists():
        print("ERROR: requirements.txt not found!")
        sys.exit(1)

    # 下载所有平台的wheel（通用包 + win + linux）
    cmds = [
        f'pip download -r "{req_file}" -d "{OFFLINE_DIR}" --only-binary=:all:',
        f'pip download -r "{req_file}" -d "{OFFLINE_DIR}" --no-binary=:none: --no-deps',
    ]
    for cmd in cmds:
        run(cmd)

    # 检查下载结果
    whl_files = list(OFFLINE_DIR.glob("*.whl")) + list(OFFLINE_DIR.glob("*.tar.gz"))
    if not whl_files:
        print("WARNING: No packages downloaded! Check network and requirements.txt")
    else:
        print(f"  Downloaded {len(whl_files)} packages")

    # Step 3: 复制项目文件
    print("\n[3/5] Copying project files...")
    copy_items = [
        ("src", "src"),
        ("playbooks", "playbooks"),
        ("skills", "skills"),
        ("scripts", "scripts"),
        ("pyproject.toml", "pyproject.toml"),
        ("requirements.txt", "requirements.txt"),
        ("config.yaml", "config.yaml"),
        ("README.md", "README.md"),
        ("LICENSE", "LICENSE"),
    ]
    for src_name, dst_name in copy_items:
        src = ROOT / src_name
        dst = DIST_DIR / dst_name
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            print(f"  Copied dir: {src_name}")
        elif src.is_file():
            shutil.copy2(src, dst)
            print(f"  Copied file: {src_name}")

    # 复制离线包
    shutil.copytree(OFFLINE_DIR, DIST_DIR / "offline_pkgs")
    print(f"  Copied offline_pkgs ({len(whl_files)} packages)")

    # Step 4: 打包
    print("\n[4/5] Creating archive...")
    if ARCHIVE.exists():
        ARCHIVE.unlink()

    # 用Python的tarfile打包
    import tarfile
    with tarfile.open(ARCHIVE, "w") as tar:
        tar.add(DIST_DIR, arcname="offline_dist")

    size_mb = ARCHIVE.stat().st_size / (1024 * 1024)
    print(f"  Archive: {ARCHIVE}")
    print(f"  Size: {size_mb:.1f} MB")

    # Step 5: 清理
    print("\n[5/5] Done!")
    print()
    print("=" * 50)
    print(f"Offline package: {ARCHIVE} ({size_mb:.1f} MB)")
    print(f"Contains: {len(whl_files)} wheel packages")
    print()
    print("Transfer this file to the internal network,")
    print("then run: python scripts/install_offline.py")
    print("=" * 50)


if __name__ == "__main__":
    main()
