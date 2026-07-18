target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/fsm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/node_lifecycle_fsm.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/fsm.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/node_lifecycle_fsm.hpp
)
