add_library(smo_acl STATIC)
target_include_directories(smo_acl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_acl PUBLIC smo_core)
smo_set_warnings(smo_acl)
smo_set_optimisation(smo_acl)

add_subdirectory(policy)
add_subdirectory(presets)
add_subdirectory(revocation)
