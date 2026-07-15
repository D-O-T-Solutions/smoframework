target_sources(smo_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sandbox.cpp
)

target_sources(smo_runtime INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/sandbox.hpp
)
