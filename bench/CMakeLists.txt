# ── Benchmark Harness (Google Benchmark + Catch2) ──────────────────────

# Enable benchmarks only when explicitly requested
option(BUILD_BENCHMARKS "Build benchmark targets" OFF)

if(NOT BUILD_BENCHMARKS)
    message(STATUS "Benchmarks disabled. Use -DBUILD_BENCHMARKS=ON to enable.")
    return()
endif()

# Google Benchmark targets
add_subdirectory(tcp_sessions)
add_subdirectory(udp_targets)
add_subdirectory(gossip_throughput)
add_subdirectory(anti_entropy)

# Catch2 test for benchmark validation
add_executable(smo_benchmark_tests
    tests/benchmark_validation.cpp
)
target_link_libraries(smo_benchmark_tests PRIVATE
    smo_core smo_protocol smo_transport smo_storage smo_trust
    smo_acl smo_contract smo_runtime
    smo_suite1_classical smo_suite2_modern
    Catch2::Catch2WithMain
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(smo_benchmark_tests PRIVATE smo_suite3_purepqc)
endif()
smo_set_warnings(smo_benchmark_tests)
smo_set_optimisation(smo_benchmark_tests)
add_test(NAME benchmark_validation COMMAND smo_benchmark_tests)

# Benchmark runner script target
add_custom_target(run_all_benchmarks
    COMMAND ${CMAKE_COMMAND} -E echo "Running all benchmarks..."
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/tcp_sessions/tcp_sessions_benchmark --benchmark_out=${CMAKE_CURRENT_BINARY_DIR}/tcp_sessions.json --benchmark_out_format=json
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/udp_targets/udp_targets_benchmark --benchmark_out=${CMAKE_CURRENT_BINARY_DIR}/udp_targets.json --benchmark_out_format=json
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/gossip_throughput/gossip_benchmark --benchmark_out=${CMAKE_CURRENT_BINARY_DIR}/gossip.json --benchmark_out_format=json
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/anti_entropy/anti_entropy_benchmark --benchmark_out=${CMAKE_CURRENT_BINARY_DIR}/anti_entropy.json --benchmark_out_format=json
    COMMENT "Running all benchmarks and producing JSON output"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)