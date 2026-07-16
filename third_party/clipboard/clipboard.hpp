#pragma once

#include <string>
#include <cstdint>

namespace smo {

// ---------------------------------------------------------------------------
// Clipboard Backend — auto-detected at runtime
// ---------------------------------------------------------------------------
enum class ClipboardBackend : uint8_t {
    None      = 0,  // unavailable
    Win32     = 1,  // Windows Win32 API
    Cocoa     = 2,  // macOS NSPasteboard (via pbcopy/pbpaste)
    X11       = 3,  // Linux X11 via dlopen(libX11.so)
    OSC52     = 4,  // Terminal OSC 52 escape sequence (SSH/headless)
    Stdout    = 5,  // Fallback: print data to stdout
};

struct ClipboardCaps {
    bool copy  = false;
    bool paste = false;
};

struct ClipboardInfo {
    ClipboardBackend backend = ClipboardBackend::None;
    ClipboardCaps caps;
    const char*    name = nullptr;  // human-readable backend name
};

// ---------------------------------------------------------------------------
// Clipboard — unified interface
// ---------------------------------------------------------------------------
ClipboardInfo  clipboard_info();
ClipboardCaps  clipboard_caps();
ClipboardBackend clipboard_backend();
bool           clipboard_available();
bool           clipboard_copy(const std::string& text);
std::string    clipboard_paste();

} // namespace smo
