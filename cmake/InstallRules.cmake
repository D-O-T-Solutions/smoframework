# ── Install helper for smo libraries ─────────────────────────────────
function(smo_install_library target directory)
    install(TARGETS ${target}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )
endfunction()

# ── Install helper for smo binaries ─────────────────────────────────
function(smo_install_binary target)
    install(TARGETS ${target}
        RUNTIME DESTINATION bin
    )
endfunction()