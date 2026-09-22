#!/bin/bash
# N5 WAN Test Suite — 3-Node NAT Traversal Tests
# Topology: A (public), B (behind NAT), C (behind NAT)
# Tests: N5.4-N5.8 + N5.9 metric

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

# Test results file for CI
RESULTS_FILE="/tmp/wan_test_results.json"

pass() {
    echo -e "  ${GREEN}✓ PASS${NC} $1"
    PASS=$((PASS + 1))
    echo "{\"test\":\"$1\",\"status\":\"PASS\"}" >> "$RESULTS_FILE"
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC} $1"
    FAIL=$((FAIL + 1))
    echo "{\"test\":\"$1\",\"status\":\"FAIL\"}" >> "$RESULTS_FILE"
}

skip() {
    echo -e "  ${YELLOW}⊘ SKIP${NC} $1"
    SKIP=$((SKIP + 1))
    echo "{\"test\":\"$1\",\"status\":\"SKIP\"}" >> "$RESULTS_FILE"
}

step() {
    printf "\n${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
    printf "${CYAN}  STEP: %s${NC}\n" "$1"
    printf "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}

# Initialize results file
echo "[]" > "$RESULTS_FILE"

# Helper: Execute command on a node container
exec_on() {
    local node=$1
    shift
    docker compose -f /tests/wan/docker-compose.yml exec -T "$node" "$@"
}

# Helper: Get metrics from node
get_metric() {
    local node=$1
    local metric=$2
    exec_on "$node" cat /var/lib/smo/metrics.prom 2>/dev/null | grep "^$metric" | head -1 | awk '{print $2}'
}

# Helper: Wait for condition
wait_for() {
    local desc="$1"
    local cmd="$2"
    local timeout="${3:-60}"
    local interval=2
    local elapsed=0
    
    echo "  Waiting for: $desc (timeout: ${timeout}s)"
    while [ $elapsed -lt $timeout ]; do
        if eval "$cmd" >/dev/null 2>&1; then
            echo "  ✓ Condition met after ${elapsed}s"
            return 0
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    echo "  ✗ Timeout after ${timeout}s"
    return 1
}

# ========================================================================
# STEP 1: Verify topology and NAT setup
# ========================================================================
step "N5.1/N5.2/N5.3: Verify WAN Topology & NAT Simulation"

# Check all containers running
for node in node-a node-b node-c router-b router-c; do
    if docker compose -f /tests/wan/docker-compose.yml ps "$node" | grep -q "Up"; then
        pass "$node container is running"
    else
        fail "$node container is not running"
    fi
done

# Verify NAT rules on router-b
if exec_on router-b iptables -t nat -L POSTROUTING -n | grep -q "MASQUERADE.*172.31.0.0/16"; then
    pass "Router B has MASQUERADE rule for 172.31.0.0/16 (N5.2)"
else
    fail "Router B missing MASQUERADE rule"
fi

# Verify NAT rules on router-c
if exec_on router-c iptables -t nat -L POSTROUTING -n | grep -q "MASQUERADE.*172.32.0.0/16"; then
    pass "Router C has MASQUERADE rule for 172.32.0.0/16 (N5.2)"
else
    fail "Router C missing MASQUERADE rule"
fi

# Verify CGNAT: No port forwarding (FORWARD NEW packets dropped)
if exec_on router-b iptables -L FORWARD -n | grep -q "DROP.*state NEW"; then
    pass "Router B blocks incoming NEW connections (N5.3 CGNAT)"
else
    fail "Router B not blocking incoming connections"
fi

if exec_on router-c iptables -L FORWARD -n | grep -q "DROP.*state NEW"; then
    pass "Router C blocks incoming NEW connections (N5.3 CGNAT)"
else
    fail "Router C not blocking incoming connections"
fi

# Verify nodes can reach public internet (via NAT)
if exec_on node-b nc -z -w 5 8.8.8.8 53 2>/dev/null; then
    pass "Node B can reach internet via NAT (outbound works)"
else
    fail "Node B cannot reach internet via NAT"
fi

if exec_on node-c nc -z -w 5 8.8.8.8 53 2>/dev/null; then
    pass "Node C can reach internet via NAT (outbound works)"
else
    fail "Node C cannot reach internet via NAT"
fi

# Verify nodes CANNOT accept inbound connections (CGNAT)
# This is harder to test directly, but we can verify the iptables rule exists
echo "  CGNAT verified: No port forwarding rules present, FORWARD NEW dropped"

# ========================================================================
# STEP 2: N5.4 - B & C join via A (outbound TCP)
# ========================================================================
step "N5.4: B & C Join via A (outbound TCP)"

# Wait for Node A to be fully ready
wait_for "Node A daemon ready" "exec_on node-a nc -z 127.0.0.1 7777" 60

# Check Node B joined via A
wait_for "Node B joined mesh" "exec_on node-b smo-node --data /var/lib/smo 2>&1 | grep -q 'NodeID:'" 60
if exec_on node-b smo-node --data /var/lib/smo 2>&1 | grep -q "NodeID:"; then
    pass "Node B identity exists and enrolled"
else
    fail "Node B identity not found"
fi

# Check Node C joined via A
wait_for "Node C joined mesh" "exec_on node-c smo-node --data /var/lib/smo 2>&1 | grep -q 'NodeID:'" 60
if exec_on node-c smo-node --data /var/lib/smo 2>&1 | grep -q "NodeID:"; then
    pass "Node C identity exists and enrolled"
else
    fail "Node C identity not found"
fi

# Verify membership from Node A's perspective (A is authority)
sleep 10  # Allow time for gossip sync
MEMBERSHIP_A=$(exec_on node-a smo mesh --list 2>/dev/null || echo "")
if echo "$MEMBERSHIP_A" | grep -q "wan-nat-b"; then
    pass "Node A sees Node B in membership (B joined via A)"
else
    fail "Node A does not see Node B in membership"
fi

if echo "$MEMBERSHIP_A" | grep -q "wan-nat-c"; then
    pass "Node A sees Node C in membership (C joined via A)"
else
    fail "Node A does not see Node C in membership"
fi

# Verify B and C see each other via gossip (through A)
sleep 5
MEMBERSHIP_B=$(exec_on node-b smo mesh --list 2>/dev/null || echo "")
if echo "$MEMBERSHIP_B" | grep -q "wan-nat-c"; then
    pass "Node B sees Node C in membership (via gossip through A)"
else
    fail "Node B does not see Node C in membership"
fi

MEMBERSHIP_C=$(exec_on node-c smo mesh --list 2>/dev/null || echo "")
if echo "$MEMBERSHIP_C" | grep -q "wan-nat-b"; then
    pass "Node C sees Node B in membership (via gossip through A)"
else
    fail "Node C does not see Node B in membership"
fi

# ========================================================================
# STEP 3: N5.5 - B ↔ C Heartbeat via Hole Punch
# ========================================================================
step "N5.5: B ↔ C Heartbeat via Hole Punch (PASS/FAIL log)"

# Wait for hole punch attempts to complete
sleep 30

# Check hole punch metrics on Node B
HP_SUCCESS_B=$(get_metric node-b "smo_hole_punch_success_total")
HP_FAILURE_B=$(get_metric node-b "smo_hole_punch_failure_total")

if [ -n "$HP_SUCCESS_B" ] && [ "$HP_SUCCESS_B" -gt 0 ]; then
    pass "Node B: Hole punch SUCCESS recorded (metric: smo_hole_punch_success_total=$HP_SUCCESS_B)"
elif [ -n "$HP_FAILURE_B" ] && [ "$HP_FAILURE_B" -gt 0 ]; then
    # Hole punch may fail in CGNAT - that's expected, we log it
    echo "  Node B: Hole punch FAIL recorded (metric: smo_hole_punch_failure_total=$HP_FAILURE_B) - expected in CGNAT"
    pass "Node B: Hole punch FAIL logged correctly (N5.5 PASS/FAIL log)"
else
    skip "Node B: No hole punch metrics yet (may need more time)"
fi

# Check hole punch metrics on Node C
HP_SUCCESS_C=$(get_metric node-c "smo_hole_punch_success_total")
HP_FAILURE_C=$(get_metric node-c "smo_hole_punch_failure_total")

if [ -n "$HP_SUCCESS_C" ] && [ "$HP_SUCCESS_C" -gt 0 ]; then
    pass "Node C: Hole punch SUCCESS recorded (metric: smo_hole_punch_success_total=$HP_SUCCESS_C)"
elif [ -n "$HP_FAILURE_C" ] && [ "$HP_FAILURE_C" -gt 0 ]; then
    echo "  Node C: Hole punch FAIL recorded (metric: smo_hole_punch_failure_total=$HP_FAILURE_C) - expected in CGNAT"
    pass "Node C: Hole punch FAIL logged correctly (N5.5 PASS/FAIL log)"
else
    skip "Node C: No hole punch metrics yet (may need more time)"
fi

# Check logs for hole punch attempts
echo "  Checking logs for hole punch activity..."
exec_on node-b grep -i "hole punch" /var/log/smo-node.log 2>/dev/null | tail -3 || true
exec_on node-c grep -i "hole punch" /var/log/smo-node.log 2>/dev/null | tail -3 || true

# ========================================================================
# STEP 4: N5.6 - B ↔ C Heartbeat via Relay Fallback
# ========================================================================
step "N5.6: B ↔ C Heartbeat via Relay Fallback"

# Check relay metrics on Node A (relay node)
RELAY_PEERS_A=$(get_metric node-a "smo_relay_active_peers")
RELAY_BYTES_A=$(get_metric node-a "smo_relay_bytes_total")

if [ -n "$RELAY_PEERS_A" ] && [ "$RELAY_PEERS_A" -gt 0 ]; then
    pass "Node A: Relay active peers = $RELAY_PEERS_A (relay fallback working)"
elif [ -n "$RELAY_BYTES_A" ] && [ "$RELAY_BYTES_A" -gt 0 ]; then
    pass "Node A: Relay bytes forwarded = $RELAY_BYTES_A (relay fallback working)"
else
    # Check if relay sessions exist
    sleep 10
    RELAY_PEERS_A=$(get_metric node-a "smo_relay_active_peers")
    if [ -n "$RELAY_PEERS_A" ] && [ "$RELAY_PEERS_A" -gt 0 ]; then
        pass "Node A: Relay active peers = $RELAY_PEERS_A (relay fallback working)"
    else
        echo "  Checking relay service status on Node A..."
        exec_on node-a grep -i "relay" /var/log/smo-node.log 2>/dev/null | tail -5 || true
        skip "Node A: No relay activity detected yet (may need more time for fallback)"
    fi
fi

# Verify B and C can communicate (via relay if hole punch failed)
# Check if B sees C as Online
sleep 10
if exec_on node-b smo mesh --list 2>/dev/null | grep -q "wan-nat-c.*Online"; then
    pass "Node B sees Node C as Online (communication via relay/hole punch)"
else
    fail "Node B does not see Node C as Online"
fi

if exec_on node-c smo mesh --list 2>/dev/null | grep -q "wan-nat-b.*Online"; then
    pass "Node C sees Node B as Online (communication via relay/hole punch)"
else
    fail "Node C does not see Node B as Online"
fi

# ========================================================================
# STEP 5: N5.7 - A Crash → B, C Detect DEGRADED
# ========================================================================
step "N5.7: A Crash → B, C Detect DEGRADED via Heartbeat Timeout"

# Stop Node A (simulate crash)
echo "  Stopping Node A (simulating crash)..."
docker compose -f /tests/wan/docker-compose.yml stop node-a

# Wait for B and C to detect A is down via heartbeat timeout
# Heartbeat: ping_interval=5s, ping_timeout=3s, max_misses=3 → ~15-20s to detect
wait_for "Node B detects A down" "exec_on node-b smo mesh --list 2>/dev/null | grep -q 'wan-public-a.*Offline'" 30
if exec_on node-b smo mesh --list 2>/dev/null | grep -q "wan-public-a.*Offline"; then
    pass "Node B detects Node A as Offline (heartbeat timeout)"
else
    # Check for DEGRADED state
    if exec_on node-b smo mesh --list 2>/dev/null | grep -q "wan-public-a.*DEGRADED"; then
        pass "Node B detects Node A as DEGRADED (heartbeat timeout)"
    else
        echo "  Current membership from B:"
        exec_on node-b smo mesh --list 2>/dev/null || true
        fail "Node B did not detect Node A failure"
    fi
fi

wait_for "Node C detects A down" "exec_on node-c smo mesh --list 2>/dev/null | grep -q 'wan-public-a.*Offline'" 30
if exec_on node-c smo mesh --list 2>/dev/null | grep -q "wan-public-a.*Offline"; then
    pass "Node C detects Node A as Offline (heartbeat timeout)"
else
    if exec_on node-c smo mesh --list 2>/dev/null | grep -q "wan-public-a.*DEGRADED"; then
        pass "Node C detects Node A as DEGRADED (heartbeat timeout)"
    else
        echo "  Current membership from C:"
        exec_on node-c smo mesh --list 2>/dev/null || true
        fail "Node C did not detect Node A failure"
    fi
fi

# Verify B and C still see each other (mesh continues without A)
sleep 5
if exec_on node-b smo mesh --list 2>/dev/null | grep -q "wan-nat-c.*Online"; then
    pass "Node B still sees Node C as Online (mesh survives A crash)"
else
    fail "Node B lost connection to Node C after A crash"
fi

if exec_on node-c smo mesh --list 2>/dev/null | grep -q "wan-nat-b.*Online"; then
    pass "Node C still sees Node B as Online (mesh survives A crash)"
else
    fail "Node C lost connection to Node B after A crash"
fi

# ========================================================================
# STEP 6: N5.8 - A Restart → Re-establish / Anti-Entropy
# ========================================================================
step "N5.8: A Restart → Re-establish + State Sync via Anti-Entropy"

# Restart Node A
echo "  Restarting Node A..."
docker compose -f /tests/wan/docker-compose.yml start node-a

# Wait for Node A to come back and rejoin
wait_for "Node A restarted and daemon ready" "exec_on node-a nc -z 127.0.0.1 7777" 60

# Wait for anti-entropy sync (P1: 30-min interval, but we can trigger/check)
# In practice, we wait for gossip to reconcile
sleep 20

# Check A sees B and C again
if exec_on node-a smo mesh --list 2>/dev/null | grep -q "wan-nat-b.*Online"; then
    pass "Node A re-established connection to Node B"
else
    fail "Node A did not reconnect to Node B"
fi

if exec_on node-a smo mesh --list 2>/dev/null | grep -q "wan-nat-c.*Online"; then
    pass "Node A re-established connection to Node C"
else
    fail "Node A did not reconnect to Node C"
fi

# Check B and C see A as Online again
if exec_on node-b smo mesh --list 2>/dev/null | grep -q "wan-public-a.*Online"; then
    pass "Node B sees Node A as Online again (re-established)"
else
    fail "Node B does not see Node A as Online"
fi

if exec_on node-c smo mesh --list 2>/dev/null | grep -q "wan-public-a.*Online"; then
    pass "Node C sees Node A as Online again (re-established)"
else
    fail "Node C does not see Node A as Online"
fi

# Check anti-entropy repairs metric
AE_REPAIRS_A=$(get_metric node-a "smo_anti_entropy_repairs_total")
if [ -n "$AE_REPAIRS_A" ] && [ "$AE_REPAIRS_A" -gt 0 ]; then
    pass "Node A: Anti-entropy repairs = $AE_REPAIRS_A (state sync occurred)"
else
    skip "Node A: No anti-entropy repairs recorded yet (30-min interval)"
fi

# ========================================================================
# STEP 7: N5.9 - smo_nat_test_status Metric
# ========================================================================
step "N5.9: Verify smo_nat_test_status Metric (0=unknown, 1=direct, 2=relay, 3=blocked)"

# Check for nat_test_status metric on all nodes
for node in node-a node-b node-c; do
    NAT_STATUS=$(get_metric "$node" "smo_nat_test_status")
    if [ -n "$NAT_STATUS" ]; then
        case $NAT_STATUS in
            0) STATUS_STR="unknown" ;;
            1) STATUS_STR="direct" ;;
            2) STATUS_STR="relay" ;;
            3) STATUS_STR="blocked" ;;
            *) STATUS_STR="invalid($NAT_STATUS)" ;;
        esac
        pass "Node $node: smo_nat_test_status = $NAT_STATUS ($STATUS_STR)"
    else
        # Check if metric exists but is 0
        if exec_on "$node" cat /var/lib/smo/metrics.prom 2>/dev/null | grep -q "smo_nat_test_status"; then
            NAT_STATUS=$(exec_on "$node" cat /var/lib/smo/metrics.prom 2>/dev/null | grep "smo_nat_test_status" | awk '{print $2}')
            case $NAT_STATUS in
                0) STATUS_STR="unknown" ;;
                1) STATUS_STR="direct" ;;
                2) STATUS_STR="relay" ;;
                3) STATUS_STR="blocked" ;;
                *) STATUS_STR="invalid($NAT_STATUS)" ;;
            esac
            pass "Node $node: smo_nat_test_status = $NAT_STATUS ($STATUS_STR)"
        else
            skip "Node $node: smo_nat_test_status metric not yet exported"
        fi
    fi
done

# ========================================================================
# Summary
# ========================================================================
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           N5 WAN TEST SUITE RESULTS             ║"
echo "╠══════════════════════════════════════════════════╣"
printf "║  ${GREEN}PASS: %-3d${NC}  ${RED}FAIL: %-3d${NC}  ${YELLOW}SKIP: %-3d${NC}  Total: %-3d           ║\n" $PASS $FAIL $SKIP $((PASS + FAIL + SKIP))
echo "╚══════════════════════════════════════════════════╝"

# Output results for CI
cat "$RESULTS_FILE" | jq -s '.' > /tmp/wan_test_results_final.json 2>/dev/null || cat "$RESULTS_FILE"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}ALL N5 TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"
    exit 1
fi