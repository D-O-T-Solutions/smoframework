target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/join_token.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/auto_enroll.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/join_token.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/auto_enroll.hpp
)
