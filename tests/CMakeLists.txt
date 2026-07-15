enable_testing()

# ── Test executable ──────────────────────────────────────────────────
add_executable(smo_all_tests
    unit/core_test.cpp
    unit/protocol_test.cpp
    unit/compiler_test.cpp
)

target_link_libraries(smo_all_tests PRIVATE
    smo_core smo_protocol smo_compiler smo_transport
    smo_storage smo_trust smo_acl smo_runtime
)

smo_set_warnings(smo_all_tests)
smo_set_optimisation(smo_all_tests)
smo_link_dependencies(smo_all_tests)

# ── Register tests ───────────────────────────────────────────────────
add_test(NAME core     COMMAND smo_all_tests --subtest core)
add_test(NAME protocol COMMAND smo_all_tests --subtest protocol)
add_test(NAME compiler COMMAND smo_all_tests --subtest compiler)

# Future test suites (placeholders for now):
# add_subdirectory(integration)
# add_subdirectory(mesh)
# add_subdirectory(chaos)
# add_subdirectory(replay)
# add_subdirectory(adversarial)
