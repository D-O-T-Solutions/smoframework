add_library(smo_acl STATIC
    acl.h
)
target_include_directories(smo_acl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_acl PUBLIC smo_core)
smo_set_warnings(smo_acl)
smo_set_optimisation(smo_acl)

add_subdirectory(policy)
add_subdirectory(presets)
add_subdirectory(revocation)
