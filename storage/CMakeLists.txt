add_library(smo_storage STATIC)
target_include_directories(smo_storage PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo>
)
target_link_libraries(smo_storage PUBLIC smo_core smo_protocol simdjson::simdjson)
smo_set_warnings(smo_storage)
smo_set_optimisation(smo_storage)

add_subdirectory(session_store)
add_subdirectory(trust_store)
add_subdirectory(audit_store)
add_subdirectory(dag_store)
add_subdirectory(node_store)
add_subdirectory(policy_store)
