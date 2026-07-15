target_sources(smo_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/workerpool.cpp
)

target_sources(smo_runtime INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/workerpool.hpp
)
