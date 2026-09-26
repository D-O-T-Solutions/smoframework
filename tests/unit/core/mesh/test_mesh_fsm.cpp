#include <mesh/mesh_fsm.hpp>
#include <cstdio>
#include <cstring>

using namespace smo;

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

static bool test_mesh_fsm_transitions()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Draft);

    auto r = fsm.on_event(mesh::MeshEvent::StartGenesis);
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Genesis);

    r = fsm.on_event(mesh::MeshEvent::BootstrapReady);
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Bootstrap);

    r = fsm.on_event(mesh::MeshEvent::AllSlotsFulfilled);
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Online);

    return true;
}

static bool test_mesh_fsm_invalid_transitions()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    auto r = fsm.on_event(mesh::MeshEvent::BootstrapReady);
    ASSERT(!r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Draft);

    r = fsm.on_event(mesh::MeshEvent::AllSlotsFulfilled);
    ASSERT(!r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Draft);

    r = fsm.on_event(mesh::MeshEvent::StartGenesis);
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Genesis);

    r = fsm.on_event(mesh::MeshEvent::AllSlotsFulfilled);
    ASSERT(!r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Genesis);

    return true;
}

static bool test_mesh_fsm_helpers()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    ASSERT(!fsm.is_online());
    ASSERT(!fsm.is_bootstrapping());
    ASSERT(!fsm.is_terminal());

    fsm.on_event(mesh::MeshEvent::StartGenesis);
    ASSERT(fsm.is_bootstrapping());
    ASSERT(!fsm.is_online());
    ASSERT(!fsm.is_terminal());

    fsm.on_event(mesh::MeshEvent::BootstrapReady);
    ASSERT(fsm.is_bootstrapping());
    ASSERT(!fsm.is_online());
    ASSERT(!fsm.is_terminal());

    fsm.on_event(mesh::MeshEvent::AllSlotsFulfilled);
    ASSERT(fsm.is_online());
    ASSERT(!fsm.is_bootstrapping());
    ASSERT(!fsm.is_terminal());

    fsm.on_event(mesh::MeshEvent::Archive);
    ASSERT(fsm.is_terminal());
    ASSERT(!fsm.is_online());
    ASSERT(!fsm.is_bootstrapping());

    return true;
}

static bool test_mesh_fsm_history()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    fsm.on_event(mesh::MeshEvent::StartGenesis);
    fsm.on_event(mesh::MeshEvent::BootstrapReady);
    fsm.on_event(mesh::MeshEvent::AllSlotsFulfilled);

    auto hist = fsm.recent_history(10);
    ASSERT_EQ(hist.size(), 3U);

    ASSERT_EQ(hist[0].from_state, static_cast<int64_t>(mesh::MeshState::Draft));
    ASSERT_EQ(hist[0].event, static_cast<int64_t>(mesh::MeshEvent::StartGenesis));
    ASSERT_EQ(hist[0].to_state, static_cast<int64_t>(mesh::MeshState::Genesis));

    ASSERT_EQ(hist[1].from_state, static_cast<int64_t>(mesh::MeshState::Genesis));
    ASSERT_EQ(hist[1].event, static_cast<int64_t>(mesh::MeshEvent::BootstrapReady));
    ASSERT_EQ(hist[1].to_state, static_cast<int64_t>(mesh::MeshState::Bootstrap));

    ASSERT_EQ(hist[2].from_state, static_cast<int64_t>(mesh::MeshState::Bootstrap));
    ASSERT_EQ(hist[2].event, static_cast<int64_t>(mesh::MeshEvent::AllSlotsFulfilled));
    ASSERT_EQ(hist[2].to_state, static_cast<int64_t>(mesh::MeshState::Online));

    return true;
}

static bool test_mesh_fsm_timeout_genesis_to_draft()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    fsm.on_event(mesh::MeshEvent::StartGenesis);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Genesis);

    auto r = fsm.fsm.on_timeout();
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Draft);

    return true;
}

static bool test_mesh_fsm_timeout_bootstrap_to_recovery()
{
    mesh::MeshFsm fsm;
    fsm.fsm.set_transitions(mesh::MeshFsm::default_rules());
    fsm.fsm.set_timeouts(mesh::MeshFsm::default_timeouts());
    fsm.fsm.reset(static_cast<int64_t>(mesh::MeshState::Draft));

    fsm.on_event(mesh::MeshEvent::StartGenesis);
    fsm.on_event(mesh::MeshEvent::BootstrapReady);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Bootstrap);

    auto r = fsm.fsm.on_timeout();
    ASSERT(r);
    ASSERT_EQ(fsm.current_state(), mesh::MeshState::Recovery);

    return true;
}

int main(int, char*[])
{
    printf("SMO MeshFSM — Unit Tests\n");
    printf("========================\n\n");

    TEST("MeshFSM transitions: Draft→Genesis→Bootstrap→Online") END_TEST(test_mesh_fsm_transitions());
    TEST("MeshFSM invalid transitions rejected") END_TEST(test_mesh_fsm_invalid_transitions());
    TEST("MeshFSM helper methods (is_online, is_bootstrapping, is_terminal)") END_TEST(test_mesh_fsm_helpers());
    TEST("MeshFSM history audit trail") END_TEST(test_mesh_fsm_history());
    TEST("MeshFSM timeout: Genesis→Draft") END_TEST(test_mesh_fsm_timeout_genesis_to_draft());
    TEST("MeshFSM timeout: Bootstrap→Recovery") END_TEST(test_mesh_fsm_timeout_bootstrap_to_recovery());

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