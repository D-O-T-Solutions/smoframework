target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/trust.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/witness.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/trust.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/witness.hpp
)
