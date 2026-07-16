add_library(smo_tooling INTERFACE)
target_include_directories(smo_tooling INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_tooling INTERFACE smo_clipboard)

add_subdirectory(tracing)
add_subdirectory(metrics)
add_subdirectory(profiling)
add_subdirectory(audit-viewer)
