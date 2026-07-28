add_library(smo_compiler STATIC)
target_include_directories(smo_compiler PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_compiler PUBLIC smo_core simdjson::simdjson)
smo_set_warnings(smo_compiler)
smo_set_optimisation(smo_compiler)

add_subdirectory(ast)
add_subdirectory(smir)
add_subdirectory(parser)
add_subdirectory(planner)
add_subdirectory(optimizer)
add_subdirectory(graph)
add_subdirectory(validator)
