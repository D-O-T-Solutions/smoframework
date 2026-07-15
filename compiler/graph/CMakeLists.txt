target_sources(smo_compiler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/builder.cpp
)

target_sources(smo_compiler INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/graph.h
    ${CMAKE_CURRENT_SOURCE_DIR}/builder.hpp
)
