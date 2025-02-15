#!/bin/sh
# This script installs Ollama on Linux.
# It detects the current operating system architecture and installs the appropriate version of Ollama.

set -eu

red="$( (/usr/bin/tput bold || :; /usr/bin/tput setaf 1 || :) 2>&-)"
plain="$( (/usr/bin/tput sgr0 || :) 2>&-)"

status() { echo ">>> $*" >&2; }
error() { echo "${red}ERROR:${plain} $*"; exit 1; }
warning() { echo "${red}WARNING:${plain} $*"; }

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf $TEMP_DIR; }
trap cleanup EXIT

available() { command -v $1 >/dev/null; }
require() {
    local MISSING=''
    for TOOL in $*; do
        if ! available $TOOL; then
            MISSING="$MISSING $TOOL"
        fi
    done

    echo $MISSING
}

[ "$(uname -s)" = "Linux" ] || error 'This script is intended to run on Linux only.'

OS=$(uname -s)
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $ARCH" ;;
esac

IS_WSL2=false

KERN=$(uname -r)
case "$KERN" in
    *icrosoft*WSL2 | *icrosoft*wsl2) IS_WSL2=true;;
    *icrosoft) error "Microsoft WSL1 is not currently supported. Please use WSL2 with 'wsl --set-version <distro> 2'" ;;
    *) ;;
esac

SUDO=
if [ "$(id -u)" -ne 0 ]; then
    # Running as root, no need for sudo
    if ! available sudo; then
        error "This script requires superuser permissions. Please re-run as root."
    fi

    SUDO="sudo"
fi

NEEDS=$(require curl awk grep sed tee xargs)
if [ -n "$NEEDS" ]; then
    status "ERROR: The following tools are required but missing:"
    for NEED in $NEEDS; do
        echo "  - $NEED"
    done
    exit 1
fi

for BINDIR in /usr/local/bin /usr/bin /bin; do
    echo $PATH | grep -q $BINDIR && break || continue
done

if [ -d "$BINDIR/easytier-linux-${ARCH}" ] ; then
    status "Cleaning up old version at $BINDIR/easytier-linux-${ARCH}"
    $SUDO rm -rf "$BINDIR/easytier-linux-${ARCH}"
fi

VERSION=2.1.2

status "Installing easytier to $BINDIR"
$SUDO install -o0 -g0 -m755 -d $BINDIR
status "Downloading Linux ${ARCH} bundle"
curl --fail --show-error --location --progress-bar \
    "https://github.com/EasyTier/EasyTier/releases/download/v2.1.2/easytier-linux-${ARCH}-v${VERSION}.zip" | \
    $SUDO unzip -o -d "$BINDIR"


add_config_file() {
    local config_name="easytier_public_server"
    cat > "$config_dir/${config_name}.conf" << EOF
# 实例名称
instance_name = "$config_name"
# 主机名
hostname = "$(hostname)"
# 例ID
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 虚拟IPv4地址
ipv4 = "$(generate_virtual_ip)"
# DHCP设置
dhcp = false

# 监听器列表
listeners = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
    "ws://0.0.0.0:11011/",
    "wg://0.0.0.0:11011/",
    "wss://0.0.0.0:11012/"
]

# Peer节点列表
[[peer]]
uri = "tcp://public.easytier.top:11010"

[[peer]]
uri = "udp://public.easytier.top:11010"

# RPC管理端口
rpc_portal = "127.0.0.1:15888"

[network_identity]
# 网络名称
network_name = "easytier"
# 网络密钥
network_secret = "easytier"

[flags]
# 默认协议
default_protocol = "tcp"
# TUN设备名称(使用简短名称)
dev_name = "$tun_name"
# 启用加密
enable_encryption = true
# 启用IPv6
enable_ipv6 = true
# MTU设置
mtu = 1380
# 延迟优先
latency_first = false
# 退出节点
enable_exit_node = false
# 禁用TUN
no_tun = false
# 启用smoltcp
use_smoltcp = false
# 外部网络白名单
foreign_network_whitelist = "*"

[log]
level = "info"
file = ""
EOF
}

configure_systemd() {
    if ! id ollama >/dev/null 2>&1; then
        status "Creating ollama user..."
        $SUDO useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
    fi
    if getent group render >/dev/null 2>&1; then
        status "Adding ollama user to render group..."
        $SUDO usermod -a -G render ollama
    fi
    if getent group video >/dev/null 2>&1; then
        status "Adding ollama user to video group..."
        $SUDO usermod -a -G video ollama
    fi

    status "Adding current user to ollama group..."
    $SUDO usermod -a -G ollama $(whoami)

    status "Creating ollama systemd service..."
    cat <<EOF | $SUDO tee /etc/systemd/system/ollama.service >/dev/null
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=$BINDIR/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=$PATH"

[Install]
WantedBy=default.target
EOF
    SYSTEMCTL_RUNNING="$(systemctl is-system-running || true)"
    case $SYSTEMCTL_RUNNING in
        running|degraded)
            status "Enabling and starting ollama service..."
            $SUDO systemctl daemon-reload
            $SUDO systemctl enable ollama

            start_service() { $SUDO systemctl restart ollama; }
            trap start_service EXIT
            ;;
        *)
            warning "systemd is not running"
            if [ "$IS_WSL2" = true ]; then
                warning "see https://learn.microsoft.com/en-us/windows/wsl/systemd#how-to-enable-systemd to enable it"
            fi
            ;;
    esac
}

if available systemctl; then
    configure_systemd
fi