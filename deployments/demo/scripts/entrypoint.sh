#!/bin/bash
set -euo pipefail

NODE_ROLE="${SMO_NODE_ROLE:-Member}"
NODE_NAME="${SMO_NODE_NAME:-unknown}"
NODE_PORT="${SMO_NODE_PORT:-7777}"
MESH_NAME="${SMO_MESH_NAME:-SOC-Production}"
SEED_NODE="${SMO_SEED_NODE:-}"
IS_AUTHORITY="${SMO_IS_AUTHORITY:-false}"

SMO_DATA="/var/lib/smo"
MESH_BASE_DIR="/var/lib/smo-mesh"

log() { echo "[$(date +%H:%M:%S)] $*"; }

get_mesh_dir() {
    # Find mesh directory by display name
    if [ -d "$MESH_BASE_DIR/meshes" ]; then
        for dir in "$MESH_BASE_DIR/meshes"/*/; do
            if [ -f "$dir/mesh.json" ]; then
                local name=$(grep -o '"display_name":"[^"]*"' "$dir/mesh.json" 2>/dev/null | cut -d'"' -f4)
                if [ "$name" = "$MESH_NAME" ]; then
                    echo "$dir"
                    return 0
                fi
            fi
        done
    fi
    return 1
}

phase_init() {
    log "=== Phase 1: Node Init ==="
    log "Node: $NODE_NAME, Role: $NODE_ROLE, Mesh: $MESH_NAME"
    log ""

    if [ ! -f "$SMO_DATA/identity.json" ]; then
        smo-node --init --name "$NODE_NAME" --data "$SMO_DATA"
        log "Identity created for $NODE_NAME"
    else
        # Verify identity is valid
        if smo-node --data "$SMO_DATA" 2>&1 | grep -q "NodeID:"; then
            log "Identity already exists at $SMO_DATA"
        else
            log "Identity file exists but invalid, recreating..."
            rm -f "$SMO_DATA/identity.json"
            smo-node --init --name "$NODE_NAME" --data "$SMO_DATA"
            log "Identity recreated for $NODE_NAME"
        fi
    fi

    if [ "$IS_AUTHORITY" = "true" ]; then
        local mesh_dir=$(get_mesh_dir)
        if [ -z "$mesh_dir" ] || [ ! -f "$mesh_dir/mesh.json" ]; then
            mkdir -p "$MESH_BASE_DIR/meshes"
            smo-admin --mesh-dir "$MESH_BASE_DIR" create-mesh "$MESH_NAME"
            log "Mesh '$MESH_NAME' created"
            mesh_dir=$(get_mesh_dir)
        else
            log "Mesh already exists at $mesh_dir"
        fi

        if [ -n "$mesh_dir" ] && [ -f "$mesh_dir/mesh.json" ]; then
            log "Publishing mesh..."
            smo-admin --mesh-dir "$mesh_dir" mesh publish --port "$NODE_PORT" || true
            log "Mesh published."
        fi
    fi
}

phase_enroll() {
    if [ "$IS_AUTHORITY" = "true" ]; then
        return 0
    fi

    log "=== Phase 2: Enrollment ==="
    log "Waiting for mesh to be published by authority..."

    local timeout=60
    local mesh_dir=""
    while [ $timeout -gt 0 ]; do
        mesh_dir=$(get_mesh_dir)
        if [ -n "$mesh_dir" ] && [ -f "$mesh_dir/mesh.json" ]; then
            # Check if bootstrap_configured
            if grep -q '"bootstrap_configured":true' "$mesh_dir/mesh.json" 2>/dev/null; then
                break
            fi
        fi
        sleep 1
        timeout=$((timeout - 1))
    done

    if [ -z "$mesh_dir" ] || [ ! -f "$mesh_dir/mesh.json" ]; then
        log "Warning: Mesh not published yet, will rely on seed for bootstrap"
        return 0
    fi

    log "Mesh found at $mesh_dir"

    # Export CSR
    log "Exporting CSR for signing..."
    smo-node --export "$SMO_DATA/node.csr.smor" --data "$SMO_DATA"

    # Sign CSR via authority (in demo, authority mesh dir is same)
    local auth_mesh_dir="/var/lib/smo-mesh/meshes/$(ls /var/lib/smo-mesh/meshes/ 2>/dev/null | head -1)"
    if [ -f "$auth_mesh_dir/mesh.json" ]; then
        log "Signing CSR with authority..."
        smo-admin --mesh-dir "$auth_mesh_dir" sign "$SMO_DATA/node.csr.smor" -o "$SMO_DATA/node.cert.smoc" 2>/dev/null || true

        if [ -f "$SMO_DATA/node.cert.smoc" ]; then
            log "Importing certificate..."
            smo-node --import "$SMO_DATA/node.cert.smoc" --data "$SMO_DATA"
        fi
    else
        log "Authority mesh dir not found, will use seed bootstrap"
    fi
}

phase_ready() {
    log "=== Phase 3: Starting Daemon ==="
    local daemon_args="--daemon --port $NODE_PORT --data $SMO_DATA --name $NODE_NAME"
    if [ -n "$SEED_NODE" ]; then
        daemon_args="$daemon_args --seed $SEED_NODE"
    fi
    log "Exec: smo-node $daemon_args"
    exec smo-node $daemon_args
}

case "${1:-}" in
    node-a|node-b|node-c)
        phase_init
        phase_enroll
        phase_ready
        ;;
    test)
        shift
        exec /usr/local/lib/smo-demo/test-e2e.sh "$@"
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        echo "Usage: docker run ... [node-a|node-b|node-c|test|shell]"
        exit 1
        ;;
esac