cmake_minimum_required(VERSION 3.10)
project(ShellMap)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ========================================================
# PLATFORM DETECTION & ARCHITECTURE-SPECIFIC OPTS
# ========================================================

# Detect CPU architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(ARCH "x86_64")
    add_compile_options(-march=native -mtune=native)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|armv8")
    set(ARCH "ARM64")
    add_compile_options(-march=native)
else()
    set(ARCH "GENERIC")
endif()

message(STATUS "Building for: ${CMAKE_SYSTEM_NAME} (${ARCH})")

# ========================================================
# 1. AUTO-DISCOVERY: OPENSSL (REQUIRED)
# ========================================================

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL found: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OpenSSL SSL lib: ${OPENSSL_SSL_LIBRARY}")

# ========================================================
# 2. AUTO-DISCOVERY: LIBOQS (Post-Quantum Crypto)
# ========================================================

# Try standard paths first
find_library(LIBOQS_LIB NAMES oqs)
find_path(LIBOQS_INCLUDE NAMES oqs/oqs.h)

# If not found, try user home directory
if(NOT LIBOQS_LIB OR NOT LIBOQS_INCLUDE)
    message(STATUS "LibOQS not in standard paths, searching user directories...")
    
    if(DEFINED ENV{LIBOQS_PATH})
        set(LIBOQS_SEARCH_PATH "$ENV{LIBOQS_PATH}")
    else()
        set(LIBOQS_SEARCH_PATH "$ENV{HOME}/liboqs")
    endif()
    
    find_library(LIBOQS_LIB NAMES oqs
        PATHS "${LIBOQS_SEARCH_PATH}/build/lib"
        NO_DEFAULT_PATH)
    find_path(LIBOQS_INCLUDE NAMES oqs/oqs.h
        PATHS "${LIBOQS_SEARCH_PATH}/build/include"
        NO_DEFAULT_PATH)
endif()

if(NOT LIBOQS_LIB OR NOT LIBOQS_INCLUDE)
    message(FATAL_ERROR "LibOQS not found! Install at ~/liboqs or set -DLIBOQS_PATH=/path/to/liboqs")
else()
    message(STATUS "LibOQS found: ${LIBOQS_LIB}")
    message(STATUS "LibOQS include: ${LIBOQS_INCLUDE}")
endif()

# ========================================================
# 3. AUTO-DISCOVERY: MINIUPNP (Network UPnP)
# ========================================================

find_library(MINIUPNP_LIB NAMES miniupnpc)
find_path(MINIUPNP_INCLUDE NAMES miniupnpc/miniupnpc.h upnpc.h)

if(NOT MINIUPNP_LIB OR NOT MINIUPNP_INCLUDE)
    message(WARNING "MiniUPnP not found. Building without UPnP support.")
    set(MINIUPNP_LIB "")
    set(MINIUPNP_INCLUDE "")
else()
    message(STATUS "MiniUPnP found: ${MINIUPNP_LIB}")
endif()

# ========================================================
# 4. INCLUDE DIRECTORIES
# ========================================================

include_directories(
    ${CMAKE_SOURCE_DIR}/headers
    ${OPENSSL_INCLUDE_DIR}
    ${LIBOQS_INCLUDE}
    ${MINIUPNP_INCLUDE}
    "/usr/include"
)

# ========================================================
# 5. COMPILER FLAGS & OPTIMIZATION
# ========================================================

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")

# Release build optimization
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -fno-strict-aliasing)
    message(STATUS "Build type: Release (optimized)")
else()
    add_compile_options(-g -O0)
    message(STATUS "Build type: Debug")
endif()

# Static linking for portability
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")

# ========================================================
# 6. SOURCE FILES & EXECUTABLE
# ========================================================

add_executable(shellmap_bin 
    main.cpp
    src/ProtocolManager.cpp
    src/SessionManager.cpp
    src/VerificationManager.cpp
    src/RelayManager.cpp
    src/Web3Manager.cpp
    src/CommandHandler.cpp
)

# ========================================================
# 7. LINKING
# ========================================================

target_link_libraries(shellmap_bin
    PRIVATE
    ${LIBOQS_LIB}           # Post-quantum crypto (Kyber, Falcon)
    ${OPENSSL_CRYPTO_LIBRARY}  # OpenSSL Crypto
    ${OPENSSL_SSL_LIBRARY}     # OpenSSL SSL
    ${MINIUPNP_LIB}         # UPnP (if available)
    dl                      # Dynamic loader
    pthread                 # Threading
)

# ========================================================
# 8. BUILD OUTPUT SUMMARY
# ========================================================

message(STATUS "")
message(STATUS "========== ShellMap Build Configuration ==========")
message(STATUS "Target: shellmap_bin")
message(STATUS "Architecture: ${ARCH}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  - OpenSSL: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  - LibOQS: ${LIBOQS_INCLUDE}")
if(MINIUPNP_INCLUDE)
    message(STATUS "  - MiniUPnP: ${MINIUPNP_INCLUDE}")
else()
    message(STATUS "  - MiniUPnP: <not found>")
endif()
message(STATUS "")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "Flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "=================================================")
message(STATUS "")

# ========================================================
# 9. INSTALL TARGETS (optional)
# ========================================================

install(TARGETS shellmap_bin DESTINATION bin)
