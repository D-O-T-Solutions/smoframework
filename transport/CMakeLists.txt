add_library(smo_transport STATIC
    transport.h
)
target_include_directories(smo_transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_transport PUBLIC smo_core smo_protocol)
smo_set_warnings(smo_transport)
smo_set_optimisation(smo_transport)

add_subdirectory(tcp)
add_subdirectory(quic)
add_subdirectory(relay)
add_subdirectory(framing)
add_subdirectory(serialization)
