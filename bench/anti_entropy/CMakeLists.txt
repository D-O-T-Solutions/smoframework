# ── Anti-Entropy 10k Nodes <30s Benchmark ────────────────────────────

cmake_minimum_required(VERSION 3.20)
project(anti_entropy_benchmark LANGUAGES CXX)

add_executable(anti_entropy_benchmark
    anti_entropy.cpp
)

target_link_libraries(anti_entropy_benchmark PRIVATE
    smo_core smo_protocol smo_transport smo_storage
    smo_suite1_classical smo_suite2_modern
    benchmark::benchmark_main
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(anti_entropy_benchmark PRIVATE smo_suite3_purepqc)
endif()

target_compile_options(anti_entropy_benchmark PRIVATE
    -Wno-conversion -Wno-sign-conversion -Wno-useless-cast -Wno-unused-variable
)
smo_set_optimisation(anti_entropy_benchmark)

add_test(NAME anti_entropy_benchmark COMMAND anti_entropy_benchmark --benchmark_min_time=1 --benchmark_format=console)