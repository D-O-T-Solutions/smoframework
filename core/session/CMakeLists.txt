target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_id.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_crypto_context.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_security.cpp
)

target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/session.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_id.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_crypto_context.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/session_security.hpp
)
