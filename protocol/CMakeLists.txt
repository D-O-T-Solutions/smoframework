add_library(smo_protocol STATIC)
target_include_directories(smo_protocol PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_protocol PUBLIC smo_core simdjson::simdjson)
smo_set_warnings(smo_protocol)
smo_set_optimisation(smo_protocol)

add_subdirectory(packet)
add_subdirectory(schema)
add_subdirectory(signing)
add_subdirectory(encryption)
add_subdirectory(replay)
