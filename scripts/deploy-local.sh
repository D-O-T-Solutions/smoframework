#!/bin/bash
# deploy-local.sh — One-command local setup: OpenVPN client + SMO worker node
# Usage: bash deploy-local.sh <cloud-vps-ip> <join-token>
set -euo pipefail

VPS_IP="${1:?Usage: $0 <cloud-vps-ip> <join-token>}"
JOIN_TOKEN="${2:?Usage: $0 <cloud-vps-ip> <join-token>}"
SMO_PORT="${SMO_PORT:-7777}"
NODE_NAME="${NODE_NAME:-$(hostname)}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
step() { echo -e "\n${GREEN}━━━ $1${NC}"; }
info() { echo -e "  ${CYAN}$1${NC}"; }

# ── Prerequisites ──────────────────────────────────────────────
step "1/5  Installing system dependencies"
apt-get update && apt-get install -y --no-install-recommends \
    openvpn build-essential cmake ninja-build \
    libfmt-dev git jq curl

# ── OpenVPN Client ─────────────────────────────────────────────
step "2/5  Setting up OpenVPN client"

# Create OpenVPN directory structure
mkdir -p /etc/openvpn/client

# Check if we have pre-generated client files
if [ -d "./openvpn-client" ]; then
    cp ./openvpn-client/* /etc/openvpn/client/
elif [ -f "client.ovpn" ]; then
    cp client.ovpn /etc/openvpn/client/
elif [ -f "./ca.crt" ]; then
    # Manual cert files provided
    cp ca.crt /etc/openvpn/client/
    cp client.crt /etc/openvpn/client/
    cp client.key /etc/openvpn/client/
    cp ta.key /etc/openvpn/client/
    cat > /etc/openvpn/client/client.conf << CONF
client
dev tun
proto udp
remote $VPS_IP 1194
ca /etc/openvpn/client/ca.crt
cert /etc/openvpn/client/client.crt
key /etc/openvpn/client/client.key
tls-crypt /etc/openvpn/client/ta.key
tls-version-min 1.2
cipher AES-256-GCM
auth SHA256
persist-key
persist-tun
route 10.8.0.0 255.255.255.0
verb 3
mute 20
keepalive 10 60
remote-random
reneg-sec 0
CONF
else
    err "No OpenVPN client files found!"
    err "Copy from cloud VPS: scp root@$VPS_IP:/root/openvpn-clients/<local-a|local-b>/* ./"
    err "Then re-run this script"
    exit 1
fi

systemctl enable openvpn-client@client
systemctl start openvpn-client@client

# Wait for VPN connection
info "Waiting for OpenVPN connection..."
for i in $(seq 1 30); do
    if ip addr show tun0 2>/dev/null | grep -q "inet "; then
        VPN_IP=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        info "OpenVPN connected: $VPN_IP"
        break
    fi
    sleep 1
done

if ! ip addr show tun0 2>/dev/null | grep -q "inet "; then
    err "OpenVPN failed to connect. Check /var/log/openvpn/client.log"
    # Continue anyway — may work with direct connection
fi

# ── Build & Install SMO ──────────────────────────────────────
step "3/5  Building SMO from source"
cd /root
if [ ! -d smoframework ]; then
    git clone https://github.com/D-O-T-Solutions/smoframework.git
fi
cd smoframework
git pull

mkdir -p build && cd build
cmake -S .. -B . -DCMAKE_BUILD_TYPE=Release -DWITH_PQC=ON -GNinja
ninja -j"$(nproc)" smo-node smo-cli
cp cmd/smo-node/smo-node /usr/local/bin/
cp cmd/smo-cli/smo-cli /usr/local/bin/
ln -sf /usr/local/bin/smo-cli /usr/local/bin/smo

# ── Join SMO Mesh ────────────────────────────────────────────
step "4/5  Joining mesh"
SMO_DATA="/var/lib/smo"
mkdir -p "$SMO_DATA"

smo-node --join "$JOIN_TOKEN" --data "$SMO_DATA" --name "$NODE_NAME" --port "$SMO_PORT"
info "Joined mesh successfully"

# Verify
smo-node --data "$SMO_DATA" --pubkey
PUBKEY=$(smo-node --data "$SMO_DATA" --pubkey 2>/dev/null)
info "Node public key: $PUBKEY"

step "5/5  Installing systemd service"
cp "$(dirname "$0")/smo-node.service" /etc/systemd/system/smo-node.service
systemctl daemon-reload

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              SMO Local Node — DEPLOYED                  ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  VPN IP:   $(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo 'not connected')"
echo "║  SMO port: $SMO_PORT                                    ║"
echo "║  Name:     $NODE_NAME                                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Next: smo-node --daemon --port $SMO_PORT --data $SMO_DATA --name '$NODE_NAME' --seed $VPS_IP:$SMO_PORT"
