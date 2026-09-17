#include <session/session_security.hpp>

#include <cstdio>

using namespace smo;

// ---------------------------------------------------------------------------
// Minimal test runner (mirrors tests/unit/core/session/test_session.cpp)
// ---------------------------------------------------------------------------
static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=%lld  RHS=%lld\n",                                                                       \
                   __FILE__, __LINE__, #a, #b, static_cast<long long>(a), static_cast<long long>(b));                  \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ==========================================================================
// ReplayWindow
// ==========================================================================

static bool test_window_initial_accepts_first()
{
    ReplayWindow w;
    ASSERT(!w.is_acceptable(0));
    ASSERT(w.is_acceptable(1));
    ASSERT(w.commit(1));
    ASSERT_EQ(w.highest(), 1U);
    return true;
}

static bool test_window_monotonic_sequence()
{
    ReplayWindow w;
    for (uint64_t seq = 1; seq <= 128; ++seq)
    {
        ASSERT(w.is_acceptable(seq));
        ASSERT(w.commit(seq));
        ASSERT_EQ(w.highest(), seq);
    }
    return true;
}

static bool test_window_duplicate_rejected()
{
    ReplayWindow w;
    ASSERT(w.commit(5));
    ASSERT(!w.is_acceptable(5));
    ASSERT(!w.commit(5));
    return true;
}

static bool test_window_out_of_order_within_window()
{
    ReplayWindow w;
    ASSERT(w.commit(100));
    ASSERT(w.is_acceptable(99));
    ASSERT(w.commit(99));
    ASSERT(!w.is_acceptable(99));

    // diff = 100 - 37 = 63 (inside the 64-bit window) => acceptable
    ASSERT(w.is_acceptable(37));
    ASSERT(w.commit(37));
    ASSERT(!w.is_acceptable(37));

    // diff = 100 - 36 = 64 (outside the window) => stale
    ASSERT(!w.is_acceptable(36));
    ASSERT(!w.commit(36));
    return true;
}

static bool test_window_precheck_does_not_mutate()
{
    ReplayWindow w;
    ASSERT(w.is_acceptable(100));
    ASSERT_EQ(w.highest(), 0U);
    ASSERT(w.commit(100));
    ASSERT_EQ(w.highest(), 100U);
    return true;
}

static bool test_window_large_jump_clears_window()
{
    ReplayWindow w;
    ASSERT(w.commit(100));
    ASSERT(w.commit(50));

    // Jump far beyond the window: old bits are discarded.
    ASSERT(w.commit(200));
    ASSERT_EQ(w.highest(), 200U);
    ASSERT(w.is_acceptable(150)); // diff 50, unseen
    ASSERT(w.is_acceptable(137)); // diff 63, unseen
    ASSERT(!w.is_acceptable(136)); // diff 64, stale
    return true;
}

static bool test_window_reset()
{
    ReplayWindow w;
    ASSERT(w.commit(42));
    ASSERT(!w.is_acceptable(42));

    w.reset();
    ASSERT_EQ(w.highest(), 0U);
    ASSERT(w.is_acceptable(42));
    ASSERT(w.commit(42));
    return true;
}

// ==========================================================================
// SessionSecurityState
// ==========================================================================

static bool test_security_state_defaults()
{
    SessionSecurityState s;
    ASSERT_EQ(s.epoch, 0U);
    ASSERT_EQ(s.tx_sequence, 0U);
    ASSERT_EQ(s.rx_epoch, 0U);
    ASSERT(s.session_id.is_zero());
    return true;
}

static bool test_security_state_rekey_invariant()
{
    SessionSecurityState s;
    s.tx_sequence = 17;
    s.epoch = 3;
    s.rx_epoch = 3;
    ASSERT(s.rx_window.commit(9));

    s.rekey();

    // Q11: epoch++, sequence reset, replay window reset.
    ASSERT_EQ(s.epoch, 4U);
    ASSERT_EQ(s.rx_epoch, 4U);
    ASSERT_EQ(s.tx_sequence, 0U);
    ASSERT_EQ(s.rx_window.highest(), 0U);
    ASSERT(s.rx_window.is_acceptable(1));
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO Session Security — Unit Tests\n");
    printf("=================================\n\n");

    TEST("ReplayWindow initial first seq") END_TEST(test_window_initial_accepts_first());
    TEST("ReplayWindow monotonic sequence") END_TEST(test_window_monotonic_sequence());
    TEST("ReplayWindow duplicate rejected") END_TEST(test_window_duplicate_rejected());
    TEST("ReplayWindow out-of-order in window") END_TEST(test_window_out_of_order_within_window());
    TEST("ReplayWindow precheck no mutate") END_TEST(test_window_precheck_does_not_mutate());
    TEST("ReplayWindow large jump clears") END_TEST(test_window_large_jump_clears_window());
    TEST("ReplayWindow reset") END_TEST(test_window_reset());
    TEST("SessionSecurityState defaults") END_TEST(test_security_state_defaults());
    TEST("SessionSecurityState rekey invariant") END_TEST(test_security_state_rekey_invariant());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}
