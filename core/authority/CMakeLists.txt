target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/registry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/authority.cpp
)
target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/registry.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/authority.hpp
)
target_link_libraries(smo_core PUBLIC smo_sqlite3)
