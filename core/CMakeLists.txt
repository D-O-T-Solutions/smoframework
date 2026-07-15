add_library(smo_core INTERFACE)
target_include_directories(smo_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# ── Sub-modules ──────────────────────────────────────────────────────
add_subdirectory(intent)
add_subdirectory(opcode)
add_subdirectory(capability)
add_subdirectory(session)
add_subdirectory(state)
add_subdirectory(errors)
