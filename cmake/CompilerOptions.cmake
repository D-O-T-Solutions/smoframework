# ── Strict warning flags ─────────────────────────────────────────────
function(smo_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wshadow -Wnon-virtual-dtor
            -Wold-style-cast -Wcast-align
            -Woverloaded-virtual -Wconversion
            -Wsign-conversion -Wnull-dereference
            -Wformat=2 -Wmisleading-indentation
            -Wduplicated-cond -Wduplicated-branches
            -Wlogical-op -Wuseless-cast
        )
    endif()
endfunction()

# ── Zero-copy / optimisation flags ───────────────────────────────────
function(smo_set_optimisation target)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(${target} PRIVATE
            -O3 -march=native -mtune=native
            -DNDEBUG
        )
    elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        target_compile_options(${target} PRIVATE -O2 -g)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_options(${target} PRIVATE -O0 -g -fsanitize=address,undefined)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

# ── Link libraries needed by every binary ────────────────────────────
function(smo_link_dependencies target)
    target_link_libraries(${target}
        PRIVATE
            smo_core
            smo_protocol
            smo_trust
            smo_acl
            fmt::fmt
            spdlog::spdlog
    )
endfunction()
