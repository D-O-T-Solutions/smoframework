target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_id.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_definition.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_abi.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_id.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_definition.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_abi.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/contract_interface.hpp
)
