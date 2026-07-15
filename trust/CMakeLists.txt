add_library(smo_trust STATIC
    trust.h
)
target_include_directories(smo_trust PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_trust PUBLIC smo_core smo_storage)
smo_set_warnings(smo_trust)
smo_set_optimisation(smo_trust)

add_subdirectory(scoring)
add_subdirectory(decay)
add_subdirectory(store)
add_subdirectory(exchange)
