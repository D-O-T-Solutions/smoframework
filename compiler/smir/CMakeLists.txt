target_sources(smo_compiler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/smir.cpp
)

target_sources(smo_compiler INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/smir.hpp
)
