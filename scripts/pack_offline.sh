#!/bin/bash
# AiCSO 离线部署包打包脚本
# 用法: bash scripts/pack_offline.sh [--platform windows|linux|all]
#
# 打包产物: aicso-offline-{platform}.tar.gz
# 内含: 源码 + 所有依赖wheel + 安装脚本

set -euo pipefail

PLATFORM="${1:---platform}"
PLATFORM_VAL="${2:-all}"

if [ "$PLATFORM" != "--platform" ]; then
    echo "用法: bash scripts/pack_offline.sh --platform windows|linux|all"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_VERSION="3.11"
BUILD_DIR="aicso-offline"
WIN_PLAT="win_amd64"
LINUX_PLAT="manylinux_2_17_x86_64"

echo "=== AiCSO 离线打包 ==="
echo "目标平台: $PLATFORM_VAL"
echo ""

# 1. 确保 uv.lock 最新
echo "[1/5] 生成 uv.lock ..."
uv lock --quiet

# 2. 导出 requirements.txt（无哈希，给 pip 离线用）
echo "[2/5] 导出 requirements.txt ..."
uv export --no-hashes --no-header -o requirements_offline.txt
# 移除 -e . 行（pip download 不支持 editable）
grep -v '^[-]e \.$' requirements_offline.txt > requirements_offline.tmp
mv requirements_offline.tmp requirements_offline.txt

# 3. 下载 wheel 包
download_wheels() {
    local platform="$1"
    local dest="$2"
    echo "  下载 $platform 包 ..."
    rm -rf "$dest"
    mkdir -p "$dest"

    # 第一轮：下载 wheel（--only-binary=:all:）
    uv run pip download \
        --dest "$dest" \
        -r requirements_offline.txt \
        --python-version "$PYTHON_VERSION" \
        --platform "$platform" \
        --only-binary=:all: \
        --quiet 2>/dev/null || true

    # 第二轮：补下载无 wheel 的包（允许 sdist）
    # 通过 --no-deps 逐个尝试，跳过已有的
    while IFS='=' read -r pkg ver; do
        pkg=$(echo "$pkg" | xargs)  # trim
        [ -z "$pkg" ] && continue
        [[ "$pkg" == \#* ]] && continue
        [[ "$pkg" == ";"* ]] && continue
        [[ "$pkg" == "-e"* ]] && continue
        # 检查是否已下载
        if ls "$dest"/${pkg//-/_}-${ver}*.whl "$dest"/${pkg}-${ver}*.whl 2>/dev/null | head -1 > /dev/null 2>&1; then
            continue
        fi
        uv run pip download \
            --dest "$dest" \
            "${pkg}==${ver}" \
            --python-version "$PYTHON_VERSION" \
            --platform "$platform" \
            --no-deps \
            --quiet 2>/dev/null || true
    done < <(grep '==' requirements_offline.txt | sed 's/;.*//' | sed 's/ //g')

    local count=$(ls "$dest"/*.whl "$dest"/*.tar.gz 2>/dev/null | wc -l)
    local size=$(du -sh "$dest" 2>/dev/null | cut -f1)
    echo "  $platform: $count 个包, $size"
}

echo "[3/5] 下载依赖 wheel ..."

if [ "$PLATFORM_VAL" = "windows" ] || [ "$PLATFORM_VAL" = "all" ]; then
    download_wheels "$WIN_PLAT" "offline_pkgs_win"
fi

if [ "$PLATFORM_VAL" = "linux" ] || [ "$PLATFORM_VAL" = "all" ]; then
    download_wheels "$LINUX_PLAT" "offline_pkgs_linux"
fi

# 4. 打包函数
pack() {
    local platform_name="$1"
    local pkgs_dir="$2"

    echo ""
    echo "[4/5] 打包 $platform_name ..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    # 复制源码和配置
    cp -r src "$BUILD_DIR/"
    cp pyproject.toml uv.lock "$BUILD_DIR/"
    cp requirements_offline.txt "$BUILD_DIR/requirements.txt"
    cp config.yaml.example "$BUILD_DIR/"
    cp -r playbooks "$BUILD_DIR/" 2>/dev/null || mkdir -p "$BUILD_DIR/playbooks"
    cp -r skills "$BUILD_DIR/" 2>/dev/null || mkdir -p "$BUILD_DIR/skills"
    cp -r tests "$BUILD_DIR/" 2>/dev/null || mkdir -p "$BUILD_DIR/tests"
    cp LICENSE "$BUILD_DIR/" 2>/dev/null || true

    # 复制 wheel 包
    cp -r "$pkgs_dir" "$BUILD_DIR/offline_pkgs"

    # 生成 Linux 安装脚本
    cat > "$BUILD_DIR/install.sh" << 'INSTALLEOF'
#!/bin/bash
set -euo pipefail

echo "=== AiCSO 离线安装 ==="

# 检查 Python
if ! command -v python3 &>/dev/null; then
    echo "错误: 未找到 python3，请先安装 Python >= 3.11"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python 版本: $PY_VER"

# 检查 gcc（部分 C 扩展包需要编译）
if ! command -v gcc &>/dev/null; then
    echo "警告: 未找到 gcc，部分依赖可能安装失败"
    echo "  CentOS/RHEL: yum install gcc python3-devel"
    echo "  Debian/Ubuntu: apt install gcc python3-dev"
fi

# 创建 venv
echo "创建虚拟环境 ..."
python3 -m venv .venv
source .venv/bin/activate

# 升级 pip
pip install --upgrade pip -q 2>/dev/null || true

# 离线安装依赖
echo "安装依赖 (离线模式) ..."
pip install --no-index --find-links=offline_pkgs/ -r requirements.txt -q

# 安装项目本身
echo "安装 AiCSO ..."
pip install -e . -q

# 生成配置文件
if [ ! -f config.yaml ]; then
    cp config.yaml.example config.yaml
    echo "已生成 config.yaml，请编辑填入实际配置"
fi

echo ""
echo "=== 安装完成 ==="
echo "启动: source .venv/bin/activate && aicso-web"
echo "CLI:  source .venv/bin/activate && aicso --help"
INSTALLEOF
    chmod +x "$BUILD_DIR/install.sh"

    # 生成 Windows 安装脚本
    cat > "$BUILD_DIR/install.bat" << 'INSTALLEOF'
@echo off
chcp 65001 >nul 2>&1
echo === AiCSO 离线安装 ===

:: 检查 Python
where python >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到 python，请先安装 Python ^>= 3.11
    exit /b 1
)

:: 创建 venv
echo 创建虚拟环境 ...
python -m venv .venv
call .venv\Scripts\activate.bat

:: 离线安装依赖
echo 安装依赖 (离线模式) ...
pip install --no-index --find-links=offline_pkgs\ -r requirements.txt -q

:: 安装项目本身
echo 安装 AiCSO ...
pip install -e . -q

:: 生成配置文件
if not exist config.yaml (
    copy config.yaml.example config.yaml
    echo 已生成 config.yaml，请编辑填入实际配置
)

echo.
echo === 安装完成 ===
echo 启动: .venv\Scripts\activate ^&^& aicso-web
echo CLI:  .venv\Scripts\activate ^&^& aicso --help
pause
INSTALLEOF

    # 打 tar.gz
    local archive="aicso-offline-${platform_name}.tar.gz"
    echo "  打包 $archive ..."
    tar -czf "$archive" "$BUILD_DIR"

    # 清理
    rm -rf "$BUILD_DIR"

    local size=$(du -h "$archive" | cut -f1)
    echo "  完成: $archive ($size)"
}

# 5. 执行打包
echo "[5/5] 打包 ..."
if [ "$PLATFORM_VAL" = "windows" ]; then
    pack "windows" "offline_pkgs_win"
elif [ "$PLATFORM_VAL" = "linux" ]; then
    pack "linux" "offline_pkgs_linux"
elif [ "$PLATFORM_VAL" = "all" ]; then
    pack "windows" "offline_pkgs_win"
    pack "linux" "offline_pkgs_linux"
fi

# 清理临时文件
rm -f requirements_offline.txt
rm -rf offline_pkgs_win offline_pkgs_linux

echo ""
echo "=== 打包完成 ==="
echo "产物:"
ls -lh aicso-offline-*.tar.gz 2>/dev/null
echo ""
echo "使用方法:"
echo "  1. 将 tar.gz 传到内网机器"
echo "  2. 解压: tar -xzf aicso-offline-*.tar.gz"
echo "  3. 进入目录: cd aicso-offline"
echo "  4. 安装: bash install.sh  (Linux) 或 install.bat (Windows)"
echo "  5. 编辑 config.yaml 配置 LLM (可选) 和数据源"
echo "  6. 启动: aicso-web"
