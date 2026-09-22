include(FetchContent)

# ── Dependency: fmt (formatting) ─────────────────────────────────────
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        11.0.2
    GIT_SHALLOW    TRUE
)
set(FMT_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt)

# ── Dependency: spdlog (logging) ─────────────────────────────────────
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.14.1
    GIT_SHALLOW    TRUE
)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(spdlog)

# ── Dependency: simdjson (zero-copy JSON) ────────────────────────────
FetchContent_Declare(
    simdjson
    GIT_REPOSITORY https://github.com/simdjson/simdjson.git
    GIT_TAG        v3.10.1
    GIT_SHALLOW    TRUE
)
set(SIMDJSON_DEVELOPER_MODE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(simdjson)

# ── Dependency: liboqs (post-quantum cryptography) ───────────────────
FetchContent_Declare(
    liboqs
    GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
    GIT_TAG        0.11.0
    GIT_SHALLOW    TRUE
)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_KEM_KYBER ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_DILITHIUM ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_ML_DSA_65 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_SPHINCS_PLUS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(liboqs)

# ── Dependency: Google Benchmark ───────────────────────────────────────
FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.8.3
    GIT_SHALLOW    TRUE
)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(benchmark)

# ── Dependency: Catch2 ─────────────────────────────────────────────────
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.3
    GIT_SHALLOW    TRUE
)
set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_HELPERS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Catch2)
