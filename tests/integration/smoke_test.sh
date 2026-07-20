#!/usr/bin/env bash
# SMO E2E Smoke Test — R1 from DISCUSSION_0040 §8

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
pass=0
fail=0

pass()  { echo -e "  ${GREEN}PASS${NC}  $1"; ((pass++)); }
fail()  { echo -e "  ${RED}FAIL${NC}  $1"; ((fail++)); }

BUILD_DIR="${1:-build}"

echo "SMO E2E Smoke Test"
echo "==================="
echo ""

# ── 1. Build check ────────────────────────────────────────────────────
echo "── §1  Build  ──────────────────────────────────────────────────"
if [ -f "$BUILD_DIR/tests/smo_pct" ]; then
    pass "Build artifacts present"
else
    fail "Build artifacts missing — run cmake --build first"
fi

# ── 2. Unit tests ─────────────────────────────────────────────────────
echo ""
echo "── §2  Unit Tests  ────────────────────────────────────────────"
ctest_output=$(ctest --test-dir "$BUILD_DIR" --output-on-failure -j"$(nproc)" 2>&1 || true)
test_count=$(echo "$ctest_output" | grep -cE 'Test\s+#' || true)
if echo "$ctest_output" | grep -q "100% tests passed"; then
    pass "All $test_count ctest tests pass"
else
    fail "Some ctest tests failed"
    echo "$ctest_output" | grep -E "FAILED|errors" || true
fi

# ── 3. CLI smoke test ─────────────────────────────────────────────────
echo ""
echo "── §3  CLI  ───────────────────────────────────────────────────"
for cli in smo-cli smo-node smo-admin; do
    cli_path=$(find "$BUILD_DIR/cmd" -name "$cli" -type f 2>/dev/null | head -1)
    if [ -n "$cli_path" ]; then
        if "$cli_path" --help &>/dev/null; then
            pass "$cli --help exits successfully"
        else
            fail "$cli --help failed"
        fi
    else
        fail "$cli not built"
    fi
done

# ── 4. Library linking ────────────────────────────────────────────────
echo ""
echo "── §4  Libraries  ─────────────────────────────────────────────"
for lib in core/libsmo_core.a protocol/libsmo_protocol.a transport/libsmo_transport.a; do
    if [ -f "$BUILD_DIR/$lib" ]; then
        pass "Static library $(basename $lib) present"
    else
        fail "Static library $(basename $lib) missing"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "=============================="
total=$((pass + fail))
if [ "$fail" -eq 0 ]; then
    echo -e "${GREEN}ALL $total SMOKE CHECKS PASSED${NC}"
else
    echo -e "${RED}$fail / $total SMOKE CHECKS FAILED${NC}"
fi
exit "$fail"
