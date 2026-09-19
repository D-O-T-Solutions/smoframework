#!/bin/bash
set -e

SMO_PROJECT="/home/nguyenduccanh/shellmap_project/smoframework"
BUILD_DIR="$SMO_PROJECT/build"
NODE_CMD="$BUILD_DIR/cmd/smo-node/smo-node"

DATA_A="/tmp/smo-test/nodeA"
DATA_B="/tmp/smo-test/nodeB"
MESH_DIR="$HOME/.smo/meshes/testmesh"

LOG_A="/tmp/nodeA_debug.log"
LOG_B="/tmp/nodeB_debug.log"

JOIN_TOKEN="$(cat /tmp/join_token.txt)"

cleanup() {
    echo "Cleaning up..."
    pkill -9 -x smo-node 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

pkill -9 -x smo-node 2>/dev/null || true
sleep 1

echo "=== Starting Node A (Authority) on port 7777 ==="
$NODE_CMD --daemon --port 7777 --data "$DATA_A" --mesh-dir "$MESH_DIR" --name "NodeA" > "$LOG_A" 2>&1 &
PID_A=$!

echo "Waiting for Node A to fully start..."
sleep 5

echo "=== Starting Node B (Join) on port 7778 ==="
$NODE_CMD --daemon --port 7778 --data "$DATA_B" --name "NodeB" --join "$JOIN_TOKEN" > "$LOG_B" 2>&1 &
PID_B=$!

echo "Waiting for handshake to complete (this may take 60+ seconds for ML-DSA-65 verification)..."
sleep 90

echo "=== Logs ==="
echo "--- Node A ---"
cat "$LOG_A"
echo ""
echo "--- Node B ---"
cat "$LOG_B"