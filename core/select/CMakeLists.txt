target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/selector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/query_parser.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/selector.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/query_parser.hpp
)
