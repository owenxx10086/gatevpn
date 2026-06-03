#!/bin/bash
# =================================================================
# Eianun 完整部署脚本 (源码保护增强版)
# 作用：部署环境、注册服务、注入指令。检测到 .local_dev 时绝对不覆盖代码。
# =================================================================
set -e

# --- 配置区 ---
INSTALL_DIR="/opt/eianun-vpngate"
SERVICE_PATH="/etc/systemd/system/eianun-vpngate.service"
CMD_PATH="/usr/bin/en"
REPO_URL="https://github.com/illria/gatevpn.git"
PROTECT_FILE=".local_dev"

# --- 检查权限 ---
if [ "$(id -u)" != "0" ]; then
    echo "错误: 请使用 root 权限运行。"
    exit 1
fi

# --- 1. 安装基础环境 ---
echo ">>> 正在安装系统基础依赖..."
apt-get update -y
apt-get install -y openvpn curl git ca-certificates iptables iproute2 psmisc procps python3 iputils-ping

# --- 2. 部署源码 (核心保护逻辑) ---
echo ">>> 正在检查代码环境..."
if [ -d "$INSTALL_DIR" ]; then
    # 核心保护逻辑：如果检测到 .local_dev，严禁触碰源码
    if [ -f "$INSTALL_DIR/$PROTECT_FILE" ]; then
        echo ">>> [保护已开启] 检测到 $PROTECT_FILE，源码目录已锁定。正在跳过 Git 同步以保护您的修改。"
    else
        echo ">>> [警告] 未检测到保护锁，正在更新源码..."
        cd "$INSTALL_DIR" && git fetch --all && git reset --hard origin/main || git reset --hard origin/master
    fi
else
    echo ">>> 首次部署，正在克隆仓库..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    # 安装后自动创建保护锁
    touch "$INSTALL_DIR/$PROTECT_FILE"
    echo ">>> 已自动开启保护锁，您的后续修改将受到保护。"
fi

# --- 3. 配置 Systemd 服务 ---
echo ">>> 配置后台服务..."
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Eianun VPN Gate Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/vpngate_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable eianun-vpngate.service
systemctl restart eianun-vpngate.service

# --- 4. 注入管理命令 'en' ---
echo ">>> 创建管理命令 'en'..."
cat > "$CMD_PATH" <<EOF
#!/bin/bash
case "\$1" in
    status) systemctl status eianun-vpngate ;;
    stop)   systemctl stop eianun-vpngate ;;
    restart) systemctl restart eianun-vpngate ;;
    logs)   journalctl -u eianun-vpngate -f ;;
    *)      systemctl restart eianun-vpngate && echo "服务已重启。" ;;
esac
EOF
chmod +x "$CMD_PATH"

echo ">>> 部署完成。"
echo "您的代码位于: $INSTALL_DIR"
echo "如果您的 Python 修改还在里面，请运行: touch $INSTALL_DIR/$PROTECT_FILE"
echo "之后运行此脚本，您的代码将永远不会被重置。"
