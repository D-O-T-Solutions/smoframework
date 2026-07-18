# ── ACL / Policy Engine Module ────────────────────────────────────────
# Policy engine uses YAML for policy file loading.
# If yaml-cpp is not available system-wide, fetch from GitHub.

find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        yaml-cpp
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        GIT_TAG yaml-cpp-0.7.0
    )
    FetchContent_MakeAvailable(yaml-cpp)
endif()

add_library(smo_acl
    policy_engine.cpp
)

target_include_directories(smo_acl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo/acl>
)

target_link_libraries(smo_acl PUBLIC
    smo_core
    yaml-cpp
)

target_compile_features(smo_acl PUBLIC cxx_std_20)