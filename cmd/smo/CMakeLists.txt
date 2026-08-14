add_executable(smo main.cpp ../smo-cli/cli_application.cpp ../smo-cli/cli_context.cpp ../smo-cli/intent_parser.cpp ${CMAKE_SOURCE_DIR}/third_party/readline/readline.cpp)
target_include_directories(smo PRIVATE ${CMAKE_SOURCE_DIR}/cmd/smo-cli ${CMAKE_SOURCE_DIR}/third_party/readline)
target_link_libraries(smo PRIVATE smo_sdk smo_genesis smo_tooling smo_suite1_classical smo_suite2_modern)
if(WITH_PQC)
    target_link_libraries(smo PRIVATE smo_suite3_purepqc)
endif()
smo_set_warnings(smo)
smo_set_optimisation(smo)
smo_link_dependencies(smo)

# Suppress unused-result warning for system() call and unused functions
target_compile_options(smo PRIVATE -Wno-unused-result -Wno-unused-function -Wno-error)
