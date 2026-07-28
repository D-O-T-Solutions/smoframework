target_sources(smo_compiler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/semantic.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/final.cpp
)

target_sources(smo_compiler INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/semantic.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/final.hpp>
)
