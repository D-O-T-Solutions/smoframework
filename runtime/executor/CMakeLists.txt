target_sources(smo_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/executor.cpp
)

target_sources(smo_runtime INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/executor.hpp
)
