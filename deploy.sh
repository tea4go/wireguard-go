#!/usr/bin/env bash
# 将 wireguard-go 静态编译并部署到远程 Linux 主机的 /opt/wireguard。
#
# 关键点：使用 CGO_ENABLED=0 交叉编译纯静态二进制，产物不依赖 glibc 版本，
# 因此能在老系统（如 Ubuntu 20.04 / glibc 2.31）上直接运行，规避
# 「本地动态链接二进制因 glibc 版本不兼容而无法在远程启动」的问题。
#
# 用法:
#   ./deploy.sh                                      # 默认 tony@192.168.193.78:6443 -> /opt/wireguard
#   ./deploy.sh --version v3.0.1                     # 指定版本号（不指定则用 main.go 内置的 0.0.1）
#   ./deploy.sh --host 1.2.3.4 --user root           # 覆盖主机与用户
#   ./deploy.sh --dir /srv/wireguard                 # 覆盖安装目录
#
# 远程连接信息也可用同名环境变量覆盖:
#   REMOTE_HOST / REMOTE_PORT / REMOTE_USER / INSTALL_DIR / VERSION

set -euo pipefail

# 默认远程连接信息
REMOTE_USER="${REMOTE_USER:-tony}"
REMOTE_HOST="${REMOTE_HOST:-192.168.193.78}"
REMOTE_PORT="${REMOTE_PORT:-6443}"
INSTALL_DIR="${INSTALL_DIR:-/opt/wireguard}"
VERSION="${VERSION:-}"

# 解析命令行参数（覆盖默认值）
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)    REMOTE_HOST="$2"; shift 2 ;;
    --port)    REMOTE_PORT="$2"; shift 2 ;;
    --user)    REMOTE_USER="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "未知参数: $1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

TARGET="${REMOTE_USER}@${REMOTE_HOST}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 临时构建目录，脚本退出时自动清理
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

BUILD_TIME="$(date '+%Y-%m-%d(%H:%M:%S)')"
# 注入 BuildTime；VERSION 非空时覆盖 main.appVer（默认 main.go 内置 0.0.1）。
LDFLAGS="-s -w -X main.BuildTime=$BUILD_TIME"
[ -n "$VERSION" ] && LDFLAGS="$LDFLAGS -X main.appVer=$VERSION"

echo "==> 静态编译（CGO_ENABLED=0 / linux / amd64）..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags "$LDFLAGS" -o "$BUILD_DIR/wireguard-go" .

echo "==> 产物校验（应为 statically linked）..."
file "$BUILD_DIR/wireguard-go" | sed 's/^/    /'

echo "==> 部署到 $TARGET:$REMOTE_PORT  $INSTALL_DIR/"
ssh -p "$REMOTE_PORT" "$TARGET" "mkdir -p '$INSTALL_DIR'"
scp -P "$REMOTE_PORT" "$BUILD_DIR/wireguard-go" "$TARGET:$INSTALL_DIR/"

echo "==> 远程验证..."
ssh -p "$REMOTE_PORT" "$TARGET" "INSTALL_DIR='$INSTALL_DIR' bash -s" <<'REMOTE'
cd "$INSTALL_DIR" || exit 1
echo "    wireguard-go -> $(timeout 15 ./wireguard-go --version 2>&1 | head -1)"
REMOTE

echo "==> 完成。"
