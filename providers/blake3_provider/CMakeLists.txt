add_library(smo_blake3_provider STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3_provider.cpp
)
target_include_directories(smo_blake3_provider PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_blake3_provider PUBLIC smo_core)
target_link_libraries(smo_blake3_provider PRIVATE smo_blake3)
target_compile_options(smo_blake3_provider PRIVATE -Wall -Wextra)
