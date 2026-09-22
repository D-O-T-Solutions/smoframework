# ── Gossip 1000 msg/s Benchmark ──────────────────────────────────────

cmake_minimum_required(VERSION 3.20)
project(gossip_benchmark LANGUAGES CXX)

add_executable(gossip_benchmark
    gossip_throughput.cpp
)

target_link_libraries(gossip_benchmark PRIVATE
    smo_core smo_protocol smo_transport
    smo_suite1_classical smo_suite2_modern
    benchmark::benchmark_main
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(gossip_benchmark PRIVATE smo_suite3_purepqc)
endif()

target_compile_options(gossip_benchmark PRIVATE
    -Wno-conversion -Wno-sign-conversion -Wno-useless-cast -Wno-unused-variable
)
smo_set_optimisation(gossip_benchmark)

add_test(NAME gossip_benchmark COMMAND gossip_benchmark --benchmark_min_time=1 --benchmark_format=console)