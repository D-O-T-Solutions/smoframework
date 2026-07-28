add_library(smo_contract STATIC)
target_include_directories(smo_contract PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_contract PUBLIC
    smo_core
    smo_storage
    smo_blake3_provider
)

add_subdirectory(registry)
add_subdirectory(factory)
add_subdirectory(kernel)
