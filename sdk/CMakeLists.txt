add_library(smo_sdk INTERFACE)
target_include_directories(smo_sdk INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_sdk INTERFACE smo_core smo_protocol smo_transport)

add_subdirectory(client)
add_subdirectory(plugin)
