#!/usr/bin/env bash
#
# install-wireguard-go.sh —— 一键安装 wireguard-go 客户端并配置 systemd 开机自启
#
# 用法:
#   sudo ./install-wireguard-go.sh                 # 安装（含 systemd 开机自启）
#   sudo ./install-wireguard-go.sh --skip-systemd  # 只装二进制+配置，不装 systemd
#
# 说明:
#   - 无需编译：直接使用已部署的 wireguard-go 二进制（由 deploy.sh 部署到 /opt/wireguard）
#   - 密钥生成使用 wireguard-tools 的 wg，无 wg 时回退 openssl，不再依赖 Go
#   - 敏感配置（服务器公钥、端点等）从脚本同目录的 .env 读取；先复制 .env.example 为 .env 并填写
#   - 若 /opt/wireguard/<接口>.conf 已存在则复用（不重新生成私钥，身份不变）
#   - 首次安装会生成新密钥对，请在结尾把公钥登记到 WireGuard 服务器
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- 加载 .env（若存在）----------
# .env 用于存放敏感配置（服务器公钥、端点等），已被 .gitignore 忽略，切勿提交。
# 使用方式：复制 .env.example 为 .env 并填写真实值；也可直接用环境变量覆盖。
if [ -f "$REPO_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$REPO_DIR/.env"
  set +a
fi

# ==================== 可配置参数（优先 .env / 环境变量，其次默认值） ====================
SERVER_PUBLIC_KEY="${SERVER_PUBLIC_KEY:-<填写服务器公钥>}"
SERVER_ENDPOINT="${SERVER_ENDPOINT:-<填写服务器IP:端口>}"
CLIENT_ADDRESS="${CLIENT_ADDRESS:-192.168.190.22/32}"   # 客户端隧道地址（服务器侧需登记为 allowed-ips）
ALLOWED_IPS="${ALLOWED_IPS:-192.168.190.0/24}"          # 分流隧道路由网段
KEEPALIVE="${KEEPALIVE:-25}"
MTU="${MTU:-1420}"

INTERFACE_NAME="${INTERFACE_NAME:-wg0}"                  # 接口名 = 配置文件名
INSTALL_DIR="${INSTALL_DIR:-/opt/wireguard}"
CONF_FILE="${INSTALL_DIR}/${INTERFACE_NAME}.conf"        # 派生，勿在 .env 中覆盖
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/wireguard-go.service}"
ROUTE_SCRIPT="${INSTALL_DIR}/${INTERFACE_NAME}-route.sh" # 派生，勿在 .env 中覆盖
# ===============================================================
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

SKIP_SYSTEMD=0
for a in "$@"; do
  case "$a" in
    --skip-systemd) SKIP_SYSTEMD=1 ;;
    -h|--help)
      echo "用法: sudo $0 [--skip-systemd]"
      echo "  安装 wireguard-go 客户端到 ${INSTALL_DIR} 并配置 systemd 开机自启。"
      echo "  参数 --skip-systemd 只装二进制+配置，不装 systemd。"
      exit 0 ;;
    *) echo "未知参数: $a" >&2; exit 1 ;;
  esac
done

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 前置检查 ----------
[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo $0"

# 校验服务器参数已填写；占位符会生成无效配置、导致隧道无法建立
case "$SERVER_PUBLIC_KEY" in
  ""|*"<"*">"*) die "请先填写 SERVER_PUBLIC_KEY（服务器公钥）：编辑脚本顶部，或 SERVER_PUBLIC_KEY=... sudo -E $0" ;;
esac
case "$SERVER_ENDPOINT" in
  ""|*"<"*">"*) die "请先填写 SERVER_ENDPOINT（服务器 IP:端口）：编辑脚本顶部，或 SERVER_ENDPOINT=... sudo -E $0" ;;
esac

# 定位已部署的 wireguard-go 二进制（deploy.sh 部署到 INSTALL_DIR，或与脚本同目录）
WG_BIN="$INSTALL_DIR/wireguard-go"
[ -x "$WG_BIN" ] || WG_BIN="$REPO_DIR/wireguard-go"
[ -x "$WG_BIN" ] || die "未找到 wireguard-go 二进制，请先运行 deploy.sh 部署到 $INSTALL_DIR/"
log "使用二进制: $WG_BIN"

# ---------- 1. 密钥与配置 ----------
NEW_KEY=0
if [ -f "$CONF_FILE" ]; then
  warn "检测到已有配置 $CONF_FILE，复用（私钥保持不变）"
else
  NEW_KEY=1
  log "生成客户端密钥对 ..."
  PRIV=""; PUB=""
  if command -v wg >/dev/null 2>&1; then
    PRIV="$(wg genkey)"
    PUB="$(printf '%s\n' "$PRIV" | wg pubkey)"
  elif command -v openssl >/dev/null 2>&1; then
    openssl genpkey -algorithm X25519 -out "$WORK_DIR/key.pem" 2>/dev/null
    PRIV="$(openssl pkey -in "$WORK_DIR/key.pem" -outform DER 2>/dev/null | tail -c 32 | base64)"
    PUB="$(openssl pkey -in "$WORK_DIR/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)"
  else
    die "未找到 wg 或 openssl，无法生成密钥对"
  fi

  log "写入配置 $CONF_FILE ..."
  umask 077
  cat > "$WORK_DIR/${INTERFACE_NAME}.conf" <<EOF
[Interface]
PrivateKey = $PRIV
Address = $CLIENT_ADDRESS
MTU = $MTU

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = $ALLOWED_IPS
PersistentKeepalive = $KEEPALIVE
EOF
  chmod 600 "$WORK_DIR/${INTERFACE_NAME}.conf"
fi

# ---------- 2. 安装 ----------
log "安装到 $INSTALL_DIR ..."
install -d -m 0755 "$INSTALL_DIR"
[ "$WG_BIN" = "$INSTALL_DIR/wireguard-go" ] || install -m 0755 "$WG_BIN" "$INSTALL_DIR/wireguard-go"
[ -f "$WORK_DIR/${INTERFACE_NAME}.conf" ] && install -m 0600 "$WORK_DIR/${INTERFACE_NAME}.conf" "$CONF_FILE"

# ---------- 3. 路由脚本 + systemd ----------
if [ "$SKIP_SYSTEMD" -eq 0 ]; then
  log "生成路由脚本 $ROUTE_SCRIPT ..."
  cat > "$WORK_DIR/${INTERFACE_NAME}-route.sh" <<EOF
#!/bin/sh
IFACE=$INTERFACE_NAME
SUBNET=$ALLOWED_IPS
i=0
while [ "\$i" -lt 40 ]; do
  if ip route replace "\$SUBNET" dev "\$IFACE" 2>/dev/null; then
    exit 0
  fi
  i=\$((i+1))
  sleep 0.25
done
echo "添加路由失败: \$SUBNET dev \$IFACE" >&2
exit 1
EOF
  install -m 0755 "$WORK_DIR/${INTERFACE_NAME}-route.sh" "$ROUTE_SCRIPT"

  log "生成 systemd 单元 $SYSTEMD_UNIT ..."
  cat > "$WORK_DIR/wireguard-go.service" <<EOF
[Unit]
Description=WireGuard userspace tunnel ($INTERFACE_NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/wireguard-go -f -c $CONF_FILE
ExecStartPost=$ROUTE_SCRIPT
Restart=on-failure
RestartSec=5
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
  install -m 0644 "$WORK_DIR/wireguard-go.service" "$SYSTEMD_UNIT"

  systemctl daemon-reload
  systemctl enable --now wireguard-go.service
fi

# ---------- 4. 汇总 ----------
echo
log "安装完成："
log "  二进制 : $INSTALL_DIR/wireguard-go"
log "  配置   : $CONF_FILE"
[ "$SKIP_SYSTEMD" -eq 0 ] && log "  服务   : $SYSTEMD_UNIT (已 enable --now)"

if [ "$NEW_KEY" -eq 1 ]; then
  echo
  log "本机公钥（需登记到 WireGuard 服务器）:"
  echo "  $PUB"
  echo
  log "在服务器上执行（示例，<接口> 替换为服务器接口名）:"
  echo "  wg set <接口> peer $PUB allowed-ips $CLIENT_ADDRESS persistent-keepalive $KEEPALIVE"
else
  echo
  warn "已复用现有配置，本机密钥/公钥未变；如需重新生成，请先删除 $CONF_FILE 再运行本脚本"
fi
