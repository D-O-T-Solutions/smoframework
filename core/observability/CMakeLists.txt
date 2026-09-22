add_library(smo_observability STATIC
    http_server.cpp
    metrics_server.cpp
    otlp_exporter.cpp
)

target_include_directories(smo_observability PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/smo/observability>
)

target_link_libraries(smo_observability PUBLIC
    smo_core
    smo_runtime
)

target_compile_features(smo_observability PUBLIC cxx_std_20)

install(TARGETS smo_observability
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY .
    DESTINATION include/smo/observability
    FILES_MATCHING PATTERN "*.hpp"
)