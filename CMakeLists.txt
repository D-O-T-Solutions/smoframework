cmake_minimum_required(VERSION 3.20)
project(smo
    VERSION 0.0.2
    DESCRIPTION "Secure Mesh Operation — capability-scoped distributed execution runtime"
    LANGUAGES C CXX ASM
)

enable_testing()

# ── Feature flags ────────────────────────────────────────────────────
option(WITH_PQC "Build post-quantum crypto suites (ML-DSA, ML-KEM via liboqs)" ON)
if(WITH_PQC)
    add_compile_definitions(SMO_WITH_PQC)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Build type defaults ──────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ── Third-party libraries ────────────────────────────────────────────
add_subdirectory(third_party/sqlite3)
add_subdirectory(third_party/blake3)
add_subdirectory(third_party/monocypher)
if(WITH_PQC)
    add_subdirectory(third_party/liboqs)
endif()
add_subdirectory(third_party/clipboard)

# yaml-cpp for PolicyEngine (core/acl)
include(FetchContent)
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG yaml-cpp-0.7.0
)
FetchContent_MakeAvailable(yaml-cpp)

# ── Custom CMake modules ─────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CompilerOptions)
include(InstallRules)
include(dependencies)

# ── Modules (ordered by dependency chain) ────────────────────────────
add_subdirectory(core)
add_subdirectory(protocol)
add_subdirectory(storage)
add_subdirectory(contract)
add_subdirectory(transport)
add_subdirectory(trust)
add_subdirectory(compiler)
add_subdirectory(sdk)
add_subdirectory(providers)
add_subdirectory(tooling)
add_subdirectory(cmd)
add_subdirectory(tests)

# ── Aliases ──────────────────────────────────────────────────────────
add_library(smo::core      ALIAS smo_core)
add_library(smo::protocol  ALIAS smo_protocol)
add_library(smo::storage   ALIAS smo_storage)
add_library(smo::transport ALIAS smo_transport)
add_library(smo::trust     ALIAS smo_trust)
add_library(smo::acl       ALIAS smo_acl)
add_library(smo::compiler  ALIAS smo_compiler)
add_library(smo::runtime   ALIAS smo_runtime)
add_library(smo::sdk       ALIAS smo_sdk)
add_library(smo::blake3    ALIAS smo_blake3)
add_library(smo::blake3_provider ALIAS smo_blake3_provider)
add_library(smo::monocypher ALIAS smo_monocypher)
if(WITH_PQC)
    add_library(smo::liboqs ALIAS oqs)
    add_library(smo::suite3_purepqc ALIAS smo_suite3_purepqc)
endif()
add_library(smo::suite1_classical ALIAS smo_suite1_classical)
add_library(smo::suite2_modern ALIAS smo_suite2_modern)
add_library(smo::tooling   ALIAS smo_tooling)

# ── Public headers (umbrella install) ────────────────────────────────
install(DIRECTORY
    core/
    protocol/
    storage/
    contract/
    transport/
    trust/
    compiler/
    sdk/
    tooling/
    providers/
    DESTINATION include/smo
    FILES_MATCHING
        PATTERN "*.hpp"
        PATTERN "*.h"
    PATTERN "test*" EXCLUDE
    PATTERN "*_test*" EXCLUDE
)

# ── Install all static/interface libraries (not exported, to avoid     ──
#     cmake export errors from source-prefixed INTERFACE headers)       ──
install(TARGETS
    smo_core smo_protocol smo_transport smo_trust smo_acl
    smo_storage smo_contract smo_compiler smo_runtime
    smo_blake3_provider smo_blake3 smo_monocypher smo_clipboard
    smo_suite1_classical smo_suite2_modern
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
if(WITH_PQC)
    install(TARGETS smo_suite3_purepqc
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
    )
endif()

# ── Export targets (only binaries for find_package) ───────────────────
set(SMO_EXPORT_TARGETS smo-node smo-cli smo-admin)

install(TARGETS ${SMO_EXPORT_TARGETS} EXPORT SMO
    RUNTIME DESTINATION bin
)

# ── Export for find_package(SMO) ─────────────────────────────────────
install(EXPORT SMO
    DESTINATION lib/cmake/smo
    NAMESPACE smo::
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_SOURCE_DIR}/cmake/SMOConfig.cmake.in
    ${CMAKE_BINARY_DIR}/SMOConfig.cmake
    INSTALL_DESTINATION lib/cmake/smo
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR
)
install(FILES
    ${CMAKE_BINARY_DIR}/SMOConfig.cmake
    DESTINATION lib/cmake/smo
)

# ── CPack ────────────────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME "smo")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure Mesh Operation runtime")
set(CPACK_PACKAGE_VENDOR "SMO Contributors")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/smo-framework/smo")
set(CPACK_PACKAGE_CONTACT "SMO Team <smo@example.com>")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.35)")
set(CPACK_DEBIAN_PACKAGE_SUGGESTS "docker.io, docker-compose")

set(CPACK_GENERATOR "DEB;TGZ")
include(CPack)
