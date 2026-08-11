#!/bin/bash
# deploy-cloud.sh — One-command VPS setup: OpenVPN server + SMO node
# Usage: bash deploy-cloud.sh <vps-public-ip>
set -euo pipefail

VPS_IP="${1:?Usage: $0 <vps-public-ip>}"
SMO_PORT="${SMO_PORT:-7777}"
OPENVPN_PORT="${OPENVPN_PORT:-1194}"
SMO_BRANCH="${SMO_BRANCH:-main}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
step()  { echo -e "\n${GREEN}━━━ $1${NC}"; }
info()  { echo -e "  ${CYAN}$1${NC}"; }
err()   { echo -e "  ${RED}$1${NC}"; }

# ── Prerequisites ──────────────────────────────────────────────
step "1/8  Installing system dependencies"
apt-get update && apt-get install -y --no-install-recommends \
    openvpn easy-rsa build-essential cmake ninja-build \
    libfmt-dev git iptables-persistent net-tools jq curl

# ── OpenVPN Setup ──────────────────────────────────────────────
step "2/8  Setting up EasyRSA PKI"
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa --batch gen-req server nopass
./easyrsa --batch sign-req server server
./easyrsa gen-dh
openvpn --genkey --secret /etc/openvpn/ta.key

# Copy generated certs
cp pki/ca.crt /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/

step "3/8  Deploying OpenVPN server config"
# Copy server config and adjust
cp "$(dirname "$0")/openvpn/server.conf" /etc/openvpn/server.conf
# Adjust for real deployment
sed -i "s/port 1194/port $OPENVPN_PORT/" /etc/openvpn/server.conf

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# NAT for VPN clients (adjust if main interface is not eth0)
if iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null; then
    info "NAT rule already exists"
else
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    netfilter-persistent save
fi

systemctl enable openvpn@server
systemctl start openvpn@server
info "OpenVPN server started on port $OPENVPN_PORT"

# Generate client certificates for local machines
step "4/8  Generating client certificates"
for CLIENT in local-a local-b; do
    cd /etc/openvpn/easy-rsa
    ./easyrsa --batch gen-req $CLIENT nopass
    ./easyrsa --batch sign-req client $CLIENT
    mkdir -p /root/openvpn-clients/$CLIENT
    cp pki/ca.crt /root/openvpn-clients/$CLIENT/
    cp pki/issued/$CLIENT.crt /root/openvpn-clients/$CLIENT/
    cp pki/private/$CLIENT.key /root/openvpn-clients/$CLIENT/
    cp /etc/openvpn/ta.key /root/openvpn-clients/$CLIENT/

    # Generate client ovpn file
    cat > /root/openvpn-clients/$CLIENT/client.ovpn << OVPNCFG
client
dev tun
proto udp
remote $VPS_IP $OPENVPN_PORT
ca ca.crt
cert $CLIENT.crt
key $CLIENT.key
tls-crypt ta.key
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
OVPNCFG
    info "Client $CLIENT: /root/openvpn-clients/$CLIENT/"
done

# ── Build & Install SMO ──────────────────────────────────────
step "5/8  Building SMO from source"
cd /root
if [ ! -d smoframework ]; then
    git clone https://github.com/shellmap-project/smoframework.git
fi
cd smoframework
git checkout "$SMO_BRANCH"
git pull

mkdir -p build && cd build
cmake -S .. -B . -DCMAKE_BUILD_TYPE=Release -DWITH_PQC=ON -GNinja
ninja -j"$(nproc)" smo-node smo-admin smo-cli
cp cmd/smo-node/smo-node /usr/local/bin/
cp cmd/smo-cli/smo-cli /usr/local/bin/
cp cmd/smo-admin/smo-admin /usr/local/bin/
ln -sf /usr/local/bin/smo-cli /usr/local/bin/smo

step "6/8  Creating SMO mesh"
SMO_DATA="/var/lib/smo"
mkdir -p "$SMO_DATA"

# Initialize node identity
if [ ! -f "$SMO_DATA/identity.json" ]; then
    smo-node --init --name "cloud-node" --data "$SMO_DATA"
    info "Identity created for cloud-node"
fi

# Create mesh via genesis
MESH_NAME="SMO-Net"
if smo --data "$SMO_DATA" mesh --list 2>&1 | grep -q "$MESH_NAME"; then
    info "Mesh '$MESH_NAME' already exists"
else
    smo --data "$SMO_DATA" mesh --create "$MESH_NAME"
    smo --data "$SMO_DATA" mesh --publish
    info "Mesh '$MESH_NAME' created and published"
fi

step "7/8  Generating join token for workers"
JOIN_TOKEN=$(smo-admin --mesh "$MESH_NAME" generate-invite Worker --expire 168h --endpoint "$VPS_IP:$SMO_PORT" 2>/dev/null || \
             smo-admin --mesh-dir "$SMO_DATA/meshes/$(ls $SMO_DATA/meshes/ | head -1)" generate-invite Worker --expire 168h --endpoint "$VPS_IP:$SMO_PORT")
echo "$JOIN_TOKEN" > /root/join-token.txt
info "Join token saved to /root/join-token.txt"
info "Token: $JOIN_TOKEN"

step "8/8  Installing systemd service"
cp "$(dirname "$0")/smo-node.service" /etc/systemd/system/smo-node.service
systemctl daemon-reload

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              SMO Cloud Node — DEPLOYED                  ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  OpenVPN:   $VPS_IP:$OPENVPN_PORT                      ║"
echo "║  SMO port:  $SMO_PORT                                   ║"
echo "║  Mesh:      $MESH_NAME                                  ║"
echo "║  Join cmd:  smo-node --join <token> --port $SMO_PORT    ║"
echo "║  Token:     /root/join-token.txt                        ║"
echo "║  Clients:   /root/openvpn-clients/                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Next:"
echo "  1. Copy /root/openvpn-clients/* to local machines"
echo "  2. Run deploy-local.sh on each local machine"
