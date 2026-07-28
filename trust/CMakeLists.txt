add_library(smo_trust STATIC)
target_include_directories(smo_trust PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_trust PUBLIC smo_core smo_storage)
smo_set_warnings(smo_trust)
smo_set_optimisation(smo_trust)

add_subdirectory(scoring)
add_subdirectory(decay)
add_subdirectory(store)
add_subdirectory(exchange)
