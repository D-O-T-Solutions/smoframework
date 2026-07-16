#pragma once

#include <string>
#include <vector>

namespace smo {

// ---------------------------------------------------------------------------
// Clipboard — cross-platform clipboard read/write
//
// Linux X11:  Xlib selection API (no external tool)
// Linux Wayland: wl-clipboard protocol if available
// macOS:     NSPasteboard via pbcopy/pbpaste (built-in)
// Windows:   Win32 clipboard API via clip/powershell (built-in)
// ---------------------------------------------------------------------------

struct ClipboardData {
    std::string text;
    // Future: image, binary, etc.
};

bool clipboard_copy(const std::string& text);

// Returns text from clipboard. Empty if unavailable or empty.
std::string clipboard_paste();

bool clipboard_available();

} // namespace smo
