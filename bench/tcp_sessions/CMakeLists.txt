# ── TCP 5000 Concurrent Sessions Benchmark ────────────────────────────

cmake_minimum_required(VERSION 3.20)
project(tcp_sessions_benchmark LANGUAGES CXX)

add_executable(tcp_sessions_benchmark
    tcp_sessions.cpp
)

target_link_libraries(tcp_sessions_benchmark PRIVATE
    smo_core smo_transport smo_protocol
    smo_suite1_classical smo_suite2_modern
    benchmark::benchmark_main
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(tcp_sessions_benchmark PRIVATE smo_suite3_purepqc)
endif()

target_compile_options(tcp_sessions_benchmark PRIVATE
    -Wno-conversion -Wno-sign-conversion -Wno-useless-cast -Wno-unused-variable
)
smo_set_optimisation(tcp_sessions_benchmark)

# Add as test for CI integration
add_test(NAME tcp_sessions_benchmark COMMAND tcp_sessions_benchmark --benchmark_min_time=1 --benchmark_format=console)