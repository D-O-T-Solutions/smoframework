# ── UDP 2000 Targets Benchmark ────────────────────────────────────────

cmake_minimum_required(VERSION 3.20)
project(udp_targets_benchmark LANGUAGES CXX)

add_executable(udp_targets_benchmark
    udp_targets.cpp
)

target_link_libraries(udp_targets_benchmark PRIVATE
    smo_core smo_transport smo_protocol
    smo_suite1_classical smo_suite2_modern
    benchmark::benchmark_main
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(udp_targets_benchmark PRIVATE smo_suite3_purepqc)
endif()

target_compile_options(udp_targets_benchmark PRIVATE
    -Wno-conversion -Wno-sign-conversion -Wno-useless-cast -Wno-unused-variable
)
smo_set_optimisation(udp_targets_benchmark)

add_test(NAME udp_targets_benchmark COMMAND udp_targets_benchmark --benchmark_min_time=1 --benchmark_format=console)