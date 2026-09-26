# mesh_manager.cpp and mesh_fsm.cpp are added directly to smo_core to resolve circular
# dependency: core/bootstrap/ references MeshManager and MeshFsm, but smo_mesh
# links smo_core. Moving them into smo_core avoids the cycle.
target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mesh_manager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mesh_fsm.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/mesh_manager.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mesh_fsm.hpp
)
