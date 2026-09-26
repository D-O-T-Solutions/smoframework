cmake_minimum_required(VERSION 3.20)

# ── smo_federation ────────────────────────────────────────────────────
add_library(smo_federation
    gateway.cpp
    federation_handshake.cpp
    policy_federation.cpp
    cross_mesh_router.cpp
)

target_include_directories(smo_federation
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/smo>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(smo_federation PRIVATE
    smo_core
    smo_acl
    smo_contract
    smo_storage
    fmt::fmt
)

smo_set_warnings(smo_federation)
smo_set_optimisation(smo_federation)

# ── Install headers ───────────────────────────────────────────────────
install(FILES
    gateway.hpp
    federation_handshake.hpp
    policy_federation.hpp
    cross_mesh_router.hpp
    DESTINATION include/smo/federation
)

# ── Tests ─────────────────────────────────────────────────────────────
add_executable(smo_test_federation_gateway
    ../../../tests/unit/core/federation/test_gateway.cpp
)
target_link_libraries(smo_test_federation_gateway PRIVATE
    smo_federation
    smo_core
    smo_acl
    smo_contract
    smo_storage
    smo_suite1_classical
    fmt::fmt
)
smo_set_warnings(smo_test_federation_gateway)
smo_set_optimisation(smo_test_federation_gateway)
add_test(NAME federation_gateway_model COMMAND smo_test_federation_gateway)

add_executable(smo_test_federation_handshake
    ../../../tests/unit/core/federation/test_federation_handshake.cpp
)
target_link_libraries(smo_test_federation_handshake PRIVATE
    smo_federation
    smo_core
    smo_suite1_classical
    fmt::fmt
)
smo_set_warnings(smo_test_federation_handshake)
smo_set_optimisation(smo_test_federation_handshake)
add_test(NAME federation_handshake_model COMMAND smo_test_federation_handshake)

add_executable(smo_test_federation_policy
    ../../../tests/unit/core/federation/test_policy_federation.cpp
)
target_link_libraries(smo_test_federation_policy PRIVATE
    smo_federation
    smo_core
    smo_acl
    smo_suite1_classical
    fmt::fmt
)
smo_set_warnings(smo_test_federation_policy)
smo_set_optimisation(smo_test_federation_policy)
add_test(NAME federation_policy_model COMMAND smo_test_federation_policy)

# ── Router & E2E tests (Tier 1 - deferred to v0.0.7+) ──────────────────
# These have API mismatches with current codebase and are Tier 1 items (C2.4/C2.5)
# Uncomment when implementing C3 Channel Model, C4 NextAction 7, C5 RuntimeKernel Async
# add_executable(smo_test_federation_router
#     ../../../tests/unit/core/federation/test_cross_mesh_router.cpp
# )
# target_link_libraries(smo_test_federation_router PRIVATE
#     smo_federation
#     smo_core
#     smo_runtime
#     smo_suite1_classical
#     fmt::fmt
# )
# smo_set_warnings(smo_test_federation_router)
# smo_set_optimisation(smo_test_federation_router)
# add_test(NAME federation_router_model COMMAND smo_test_federation_router)

# ── E2E Cross-mesh test ──────────────────────────────────────────────
# add_executable(smo_test_cross_mesh_e2e
#     ../../../tests/unit/core/federation/test_cross_mesh_e2e.cpp
# )
# target_link_libraries(smo_test_cross_mesh_e2e PRIVATE
#     smo_federation
#     smo_core
#     smo_runtime
#     smo_acl
#     smo_contract
#     smo_storage
#     smo_suite1_classical
#     fmt::fmt
# )
# smo_set_warnings(smo_test_cross_mesh_e2e)
# smo_set_optimisation(smo_test_cross_mesh_e2e)
# target_compile_definitions(smo_test_cross_mesh_e2e PRIVATE SMO_TEST=1)
# add_test(NAME cross_mesh_e2e COMMAND smo_test_cross_mesh_e2e)