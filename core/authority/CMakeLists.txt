target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/registry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/authority.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/enroll_server.cpp
)
target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/registry.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/authority.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/enroll_server.hpp
)
target_link_libraries(smo_core PUBLIC smo_sqlite3)
