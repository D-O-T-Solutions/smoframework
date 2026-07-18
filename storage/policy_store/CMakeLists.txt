target_sources(smo_storage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/policy_store.cpp
)

target_sources(smo_storage INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/policy_store.h
)