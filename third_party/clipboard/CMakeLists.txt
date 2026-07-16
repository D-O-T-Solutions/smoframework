# Clipboard library — cross-platform clipboard, zero external dependencies.
#
# Linux:   dlopen(libX11.so.6) at runtime — no libX11-dev needed at build time
# macOS:   pbcopy/pbpaste (built-in)
# Windows: Win32 API (built-in)

add_library(smo_clipboard STATIC clipboard.cpp)
target_include_directories(smo_clipboard PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# On Linux we use dlopen for X11 runtime loading
if(UNIX AND NOT APPLE)
    target_link_libraries(smo_clipboard PRIVATE ${CMAKE_DL_LIBS})
endif()

