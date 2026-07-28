target_sources(smo_compiler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/builder.cpp
)

target_sources(smo_compiler INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/graph.h>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/builder.hpp>
)
