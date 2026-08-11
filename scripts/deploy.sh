#!/bin/bash
# deploy.sh — One-command deployment: auto-detect cloud vs local
# Usage:
#   bash deploy.sh cloud <vps-ip>      # Run on VPS
#   bash deploy.sh local <vps-ip> <token>  # Run on local machine
set -euo pipefail

action="${1:-help}"
case "$action" in
    cloud)
        shift
        bash "$(dirname "$0")/deploy-cloud.sh" "$@"
        ;;
    local)
        shift
        bash "$(dirname "$0")/deploy-local.sh" "$@"
        ;;
    *)
        echo "SMO Deploy — One-command deployment"
        echo ""
        echo "Usage:"
        echo "  bash deploy.sh cloud <vps-ip>                # Setup cloud authority node"
        echo "  bash deploy.sh local <vps-ip> <join-token>   # Setup local worker node"
        echo ""
        echo "Prerequisites:"
        echo "  - Ubuntu 22.04+ on all machines"
        echo "  - Root or sudo access"
        echo "  - Cloud VPS with public IP"
        echo ""
        echo "Step 1: Run on cloud VPS first"
        echo "  ssh root@<vps-ip> 'bash -s' < deploy.sh cloud <vps-ip>"
        echo ""
        echo "Step 2: Copy join token from cloud VPS"
        echo "  scp root@<vps-ip>:/root/join-token.txt ."
        echo ""
        echo "Step 3: Copy OpenVPN certs from cloud VPS"
        echo "  scp -r root@<vps-ip>:/root/openvpn-clients/<local-a>/* ./openvpn-client/"
        echo ""
        echo "Step 4: Run on each local machine"
        echo "  bash deploy.sh local <vps-ip> <join-token>"
        ;;
esac
