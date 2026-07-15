target_sources(smo_contract PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel_contracts.cpp
)

target_sources(smo_contract INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel_contracts.hpp
)
