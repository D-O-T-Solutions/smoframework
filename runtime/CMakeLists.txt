add_library(smo_runtime STATIC
    runtime.h
)
target_include_directories(smo_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(smo_runtime PUBLIC
    smo_core smo_compiler smo_transport smo_storage smo_trust smo_acl
)
smo_set_warnings(smo_runtime)
smo_set_optimisation(smo_runtime)

add_subdirectory(scheduler)
add_subdirectory(executor)
add_subdirectory(sandbox)
add_subdirectory(workerpool)
add_subdirectory(fsm)
add_subdirectory(audit)
add_subdirectory(recovery)
