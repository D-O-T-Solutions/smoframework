// SPDX-License-Identifier: MIT
//
// clipboard.cpp — Cross-platform clipboard with ZERO external dependencies.
//
// Linux:   dlopen(libX11.so.6) at runtime (no build-time dependency on X11-dev)
// Windows: Win32 API (built-in)
// macOS:   pbcopy/pbpaste (built-in)
//
// No xclip, xsel, wl-copy, or any other external tool required on any platform.

#include "clipboard.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

#if defined(__linux__)
#include <dlfcn.h>
#endif

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <ole2.h>
#endif

namespace smo {

// =========================================================================
// Helpers
// =========================================================================

namespace {

std::string exec_read(const char* cmd) {
    std::array<char, 128> buf;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return {};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get()))
        result += buf.data();
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

bool pipe_write(const std::string& data, const std::string& cmd) {
    std::string full = cmd + " 2>/dev/null";
    FILE* pipe = popen(full.c_str(), "w");
    if (!pipe) return false;
    fwrite(data.data(), 1, data.size(), pipe);
    return pclose(pipe) == 0;
}

// =========================================================================
// X11 native via dlopen — zero build-time dependency on X11-dev
// =========================================================================

#if defined(__linux__)

// Minimal X11 type forward-declarations (these match actual X11 types)
typedef unsigned long  XAtom;
typedef unsigned long  XWindow;
typedef unsigned long  XTime;
typedef long           XCD;
struct XDisplay; // opaque

// Function pointers loaded via dlsym
struct X11Procs {
    void* lib;

    XDisplay* (*OpenDisplay)(const char*);
    int       (*CloseDisplay)(XDisplay*);
    int       (*Free)(void*);
    int       (*Flush)(XDisplay*);
    int       (*EventsQueued)(XDisplay*, int);
    int       (*NextEvent)(XDisplay*, void*);
    int       (*CheckTypedEvent)(XDisplay*, int, void*);
    int       (*CheckMaskEvent)(XDisplay*, long, void*);
    int       (*SetSelectionOwner)(XDisplay*, XAtom, XWindow, XTime);
    int       (*ConvertSelection)(XDisplay*, XAtom, XAtom, XAtom, XWindow, XTime);
    XWindow   (*GetSelectionOwner)(XDisplay*, XAtom);
    XAtom     (*InternAtom)(XDisplay*, const char*, int);
    int       (*ChangeProperty)(XDisplay*, XWindow, XAtom, XAtom, int, int, const unsigned char*, int);
    int       (*GetWindowProperty)(XDisplay*, XWindow, XAtom, long, long, int, XAtom, XAtom*, int*, unsigned long*, unsigned long*, unsigned char**);
    int       (*SendEvent)(XDisplay*, XWindow, int, long, void*);
    XWindow   (*DefaultRootWindow)(XDisplay*);
    XWindow   (*CreateSimpleWindow)(XDisplay*, XWindow, int, int, int, int, unsigned int, unsigned long, unsigned long);
    int       (*DestroyWindow)(XDisplay*, XWindow);
    int       (*SetErrorHandler)(int (*)(XDisplay*, void*));
};

static X11Procs* g_x11 = nullptr;

static void x11_cleanup() {
    if (!g_x11) return;
    if (g_x11->lib) dlclose(g_x11->lib);
    delete g_x11;
    g_x11 = nullptr;
}

static bool x11_load() {
    if (g_x11) return g_x11->lib != nullptr;

    g_x11 = new X11Procs();
    std::memset(g_x11, 0, sizeof(*g_x11));

    const char* libs[] = {"libX11.so.6", "libX11.so"};
    for (auto lib : libs) {
        g_x11->lib = dlopen(lib, RTLD_LAZY | RTLD_LOCAL);
        if (g_x11->lib) break;
    }
    if (!g_x11->lib) { g_x11->lib = nullptr; return false; }

#define XLOAD(sym) do { \
    g_x11->sym = reinterpret_cast<decltype(g_x11->sym)>(dlsym(g_x11->lib, "X" #sym)); \
    if (!g_x11->sym) { dlclose(g_x11->lib); g_x11->lib = nullptr; return false; } \
} while(0)

    XLOAD(OpenDisplay);
    XLOAD(CloseDisplay);
    XLOAD(Free);
    XLOAD(Flush);
    XLOAD(EventsQueued);
    XLOAD(CheckTypedEvent);
    XLOAD(SetSelectionOwner);
    XLOAD(ConvertSelection);
    XLOAD(GetSelectionOwner);
    XLOAD(InternAtom);
    XLOAD(ChangeProperty);
    XLOAD(GetWindowProperty);
    XLOAD(SendEvent);
    XLOAD(DefaultRootWindow);
    XLOAD(CreateSimpleWindow);
    XLOAD(DestroyWindow);

    // NextEvent is optional (used only for event loop)
    dlsym(g_x11->lib, "XNextEvent"); // don't fail if not found
    std::atexit(x11_cleanup);
    return true;
}

// X11 SelectionRequest event size (we use raw buffers, no Xlib headers needed)
// XSelectionRequestEvent layout (all fields are architecture-dependent sizes):
//   type: int (4)
//   serial: unsigned long (8 on 64-bit)
//   send_event: int (4)
//   display: Display* (8)
//   owner: Window (8)
//   requestor: Window (8)
//   selection: Atom (8)
//   target: Atom (8)
//   property: Atom (8)
//   time: Time (8)
// Total = 4+8+4+8+8+8+8+8+8+8 = 72 bytes
// But we also need event type constants
#define X11_SelectionRequest 30
#define X11_SelectionNotify  31
#define X11_PropertyChangeMask (1L<<6)

static bool x11_copy(const std::string& text) {
    if (!x11_load()) return false;

    auto dpy = g_x11->OpenDisplay(nullptr);
    if (!dpy) return false;

    XAtom atom_clipboard = g_x11->InternAtom(dpy, "CLIPBOARD", 0);
    XAtom atom_utf8      = g_x11->InternAtom(dpy, "UTF8_STRING", 1);
    XAtom atom_targets   = g_x11->InternAtom(dpy, "TARGETS", 0);
    XAtom atom_prop      = g_x11->InternAtom(dpy, "SMO_CLIPBOARD", 0);
    XWindow root         = g_x11->DefaultRootWindow(dpy);

    // Create ownership window
    XWindow win = g_x11->CreateSimpleWindow(dpy, root, 0, 0, 1, 1, 0, 0, 0);

    // Store data on our window as a property
    g_x11->ChangeProperty(dpy, win, atom_prop, atom_utf8 ? atom_utf8 : XAtom(31),
                          8, 0,
                          reinterpret_cast<const unsigned char*>(text.data()),
                          static_cast<int>(text.size()));
    g_x11->SetSelectionOwner(dpy, atom_clipboard, win, XTime(0));
    g_x11->Flush(dpy);

    // Short event loop (50ms) to handle incoming SelectionRequest
    alignas(8) char ev[192]; // XEvent is 192 bytes on 64-bit
    int64_t deadline = 0;
    { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
      deadline = ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 50; }

    while (true) {
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        if (ts.tv_sec * 1000 + ts.tv_nsec / 1000000 >= deadline) break;

        if (g_x11->CheckTypedEvent(dpy, X11_SelectionRequest,
                                    reinterpret_cast<void*>(&ev))) {
            // Parse the SelectionRequest event fields from raw bytes
            // Layout (64-bit): type(4) + pad(4) + serial(8) + send_event(4) + pad(4)
            // + display(8) + owner(8) + requestor(8) + selection(8) + target(8)
            // + property(8) + time(8) = 80 bytes total
            // Offsets: owner=32, requestor=40, selection=48, target=56, property=64, time=72
            size_t off = 0;
            off += 4 + 4; // type + pad
            off += 8;     // serial
            off += 4 + 4; // send_event + pad
            off += 8;     // display
            /* XWindow owner    = */ (void)(ev + off); off += 8;
            XWindow requestor  = 0; std::memcpy(&requestor, ev + off, 8); off += 8;
            XAtom selection    = 0; std::memcpy(&selection, ev + off, 8); off += 8;
            XAtom target       = 0; std::memcpy(&target, ev + off, 8); off += 8;
            XAtom property     = 0; std::memcpy(&property, ev + off, 8); off += 8;

            // Build SelectionNotify response
            alignas(8) char resp[80];
            std::memset(resp, 0, sizeof(resp));
            int type_val = X11_SelectionNotify;
            std::memcpy(resp, &type_val, 4);
            std::memcpy(resp + 16, &dpy, 8);     // display
            std::memcpy(resp + 24, &requestor, 8); // requestor
            std::memcpy(resp + 32, &selection, 8); // selection
            std::memcpy(resp + 40, &target, 8);    // target
            if (target == atom_targets) {
                // Reply with list of supported targets
                XAtom supported[] = { XAtom(31), atom_utf8 ? atom_utf8 : XAtom(31), atom_targets };
                g_x11->ChangeProperty(dpy, requestor, property,
                                      XAtom(4), 32, 0,
                                      reinterpret_cast<unsigned char*>(supported),
                                      3);
                std::memcpy(resp + 48, &property, 8);
            } else if (target == XAtom(31) || target == atom_utf8 || target == atom_prop) {
                // Provide the text data
                g_x11->ChangeProperty(dpy, requestor, property,
                                      target, 8, 0,
                                      reinterpret_cast<const unsigned char*>(text.data()),
                                      static_cast<int>(text.size()));
                std::memcpy(resp + 48, &property, 8);
            } else {
                // Unsupported target — refuse
                XAtom none = 0;
                std::memcpy(resp + 48, &none, 8);
            }
            // Time field
            XTime t = 0; std::memcpy(resp + 56, &t, 8);

            g_x11->SendEvent(dpy, requestor, 0, 0, resp);
            g_x11->Flush(dpy);
        }
        struct timespec sl = {0, 1 * 1000000};
        nanosleep(&sl, nullptr);
    }

    g_x11->CloseDisplay(dpy);
    return true;
}

static std::string x11_paste() {
    if (!x11_load()) return {};

    auto dpy = g_x11->OpenDisplay(nullptr);
    if (!dpy) return {};

    XAtom atom_clipboard = g_x11->InternAtom(dpy, "CLIPBOARD", 0);
    XAtom atom_utf8      = g_x11->InternAtom(dpy, "UTF8_STRING", 1);
    XAtom atom_prop      = g_x11->InternAtom(dpy, "SMO_CLIPBOARD_PROP", 0);
    XWindow root         = g_x11->DefaultRootWindow(dpy);

    XWindow owner = g_x11->GetSelectionOwner(dpy, atom_clipboard);
    if (!owner) { g_x11->CloseDisplay(dpy); return {}; }

    // Request the selection
    g_x11->ConvertSelection(dpy, atom_clipboard,
                            atom_utf8 ? atom_utf8 : XAtom(31),
                            atom_prop, owner, XTime(0));
    g_x11->Flush(dpy);

    // Wait for SelectionNotify (200ms timeout)
    std::string result;
    alignas(8) char ev[192];
    int64_t deadline = 0;
    { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
      deadline = ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 200; }

    while (true) {
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        if (ts.tv_sec * 1000 + ts.tv_nsec / 1000000 >= deadline) break;

        if (g_x11->CheckTypedEvent(dpy, X11_SelectionNotify,
                                    reinterpret_cast<void*>(&ev))) {
            // Read the property set by the selection owner
            XAtom actual_type = 0;
            int actual_format = 0;
            unsigned long nitems = 0;
            unsigned long bytes_after = 0;
            unsigned char* prop_data = nullptr;

            int status = g_x11->GetWindowProperty(dpy, owner, atom_prop,
                                                   0, 65536 / 4, 1,
                                                   0, // AnyPropertyType
                                                   &actual_type, &actual_format,
                                                   &nitems, &bytes_after,
                                                   &prop_data);
            if (status == 0 && prop_data) {
                result.assign(reinterpret_cast<char*>(prop_data), nitems);
                g_x11->Free(prop_data);
            }
            break;
        }
        struct timespec sl = {0, 5 * 1000000};
        nanosleep(&sl, nullptr);
    }

    g_x11->CloseDisplay(dpy);
    return result;
}

#endif // __linux__

// =========================================================================
// Windows native backend
// =========================================================================

#if defined(_WIN32)

static bool win32_copy(const std::string& text) {
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hglb) { CloseClipboard(); return false; }
    char* buf = static_cast<char*>(GlobalLock(hglb));
    if (buf) { std::memcpy(buf, text.data(), text.size()); buf[text.size()] = 0; }
    GlobalUnlock(hglb);
    SetClipboardData(CF_TEXT, hglb);
    CloseClipboard();
    return true;
}

static std::string win32_paste() {
    if (!OpenClipboard(nullptr)) return {};
    HANDLE hglb = GetClipboardData(CF_TEXT);
    if (!hglb) { CloseClipboard(); return {}; }
    char* buf = static_cast<char*>(GlobalLock(hglb));
    std::string result;
    if (buf) result = buf;
    GlobalUnlock(hglb);
    CloseClipboard();
    return result;
}

#endif // _WIN32

// =========================================================================
// OSC 52 — clipboard escape sequence for SSH / headless terminals
//
// Works in: iTerm2, kitty, Alacritty, tmux, Windows Terminal, GNOME Terminal…
// Sends \e]52;c;<base64>\a  to stderr so the terminal emulator copies text.
// =========================================================================

static bool osc52_copy(const std::string& text) {
    // Only try if stderr is a terminal
    if (!isatty(STDERR_FILENO)) return false;

    // Base64-encode the text
    static const char kEnc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve((text.size() + 2) / 3 * 4);
    for (size_t i = 0; i < text.size(); i += 3) {
        uint32_t v = (uint32_t)(unsigned char)text[i] << 16;
        if (i + 1 < text.size()) v |= (uint32_t)(unsigned char)text[i + 1] << 8;
        if (i + 2 < text.size()) v |= (uint32_t)(unsigned char)text[i + 2];
        b64 += kEnc[(v >> 18) & 0x3f];
        b64 += kEnc[(v >> 12) & 0x3f];
        b64 += kEnc[(v >> 6) & 0x3f];
        b64 += kEnc[v & 0x3f];
    }
    size_t pad = (3 - text.size() % 3) % 3;
    for (size_t i = 0; i < pad; ++i) b64[b64.size() - 1 - i] = '=';

    // Write OSC 52 sequence to stderr
    std::fprintf(stderr, "\033]52;c;%s\a", b64.c_str());
    std::fflush(stderr);
    return true;
}

// =========================================================================
// Stdout fallback — always works, prints data with a header/footer
// =========================================================================

static bool stdout_copy(const std::string& text) {
    std::fprintf(stderr, "[clipboard] No GUI clipboard available. Data:\n");
    std::fprintf(stderr, "-----BEGIN SMO CLIPBOARD DATA-----\n");
    // Write raw data to stderr (not stdout — stdout is for command output)
    fwrite(text.data(), 1, text.size(), stderr);
    std::fprintf(stderr, "\n-----END SMO CLIPBOARD DATA-----\n");
    std::fflush(stderr);
    return true; // always "succeeds" — user can copy manually
}

// =========================================================================
// Backend auto-detection
// =========================================================================

static ClipboardBackend detect_backend() {
#if defined(__APPLE__)
    return ClipboardBackend::Cocoa;
#elif defined(_WIN32)
    return ClipboardBackend::Win32;
#else
    if (getenv("DISPLAY") && getenv("DISPLAY")[0]) {
        if (x11_load()) return ClipboardBackend::X11;
    }
    if (isatty(STDERR_FILENO)) return ClipboardBackend::OSC52;
    return ClipboardBackend::Stdout;
#endif
}

static const char* backend_name(ClipboardBackend b) {
    switch (b) {
        case ClipboardBackend::Win32:  return "Win32 Clipboard API";
        case ClipboardBackend::Cocoa:  return "Cocoa NSPasteboard";
        case ClipboardBackend::X11:    return "X11 (via dlopen)";
        case ClipboardBackend::OSC52:  return "OSC 52 terminal escape";
        case ClipboardBackend::Stdout: return "stdout fallback";
        default:                       return "none";
    }
}

} // anonymous namespace

// =========================================================================
// Public API
// =========================================================================

ClipboardInfo clipboard_info() {
    ClipboardInfo info;
    info.backend = detect_backend();
    info.name    = backend_name(info.backend);
    // Caps depend on backend
    switch (info.backend) {
        case ClipboardBackend::Win32:
        case ClipboardBackend::Cocoa:
        case ClipboardBackend::X11:
            info.caps.copy  = true;
            info.caps.paste = true;
            break;
        case ClipboardBackend::OSC52:
            info.caps.copy  = true;
            info.caps.paste = false; // OSC 52 paste not widely supported
            break;
        case ClipboardBackend::Stdout:
            info.caps.copy  = true;  // prints to stderr
            info.caps.paste = false;
            break;
        default:
            break;
    }
    return info;
}

ClipboardBackend clipboard_backend() {
    return detect_backend();
}

ClipboardCaps clipboard_caps() {
    return clipboard_info().caps;
}

bool clipboard_available() {
    return detect_backend() != ClipboardBackend::None;
}

bool clipboard_copy(const std::string& text) {
    if (text.empty()) return false;

    auto backend = detect_backend();

    switch (backend) {
#if defined(__APPLE__)
        case ClipboardBackend::Cocoa:
            return pipe_write(text, "pbcopy");
#elif defined(_WIN32)
        case ClipboardBackend::Win32:
            if (win32_copy(text)) return true;
            return pipe_write(text, "clip");
#else
        case ClipboardBackend::X11:
            return x11_copy(text);
#endif
        case ClipboardBackend::OSC52:
            return osc52_copy(text);
        case ClipboardBackend::Stdout:
            return stdout_copy(text);
        default:
            return false;
    }
}

std::string clipboard_paste() {
    auto backend = detect_backend();

    switch (backend) {
#if defined(__APPLE__)
        case ClipboardBackend::Cocoa:
            return exec_read("pbpaste");
#elif defined(_WIN32)
        case ClipboardBackend::Win32: {
            auto r = win32_paste();
            if (!r.empty()) return r;
            return exec_read("powershell -command \"Get-Clipboard\"");
        }
#else
        case ClipboardBackend::X11:
            return x11_paste();
#endif
        case ClipboardBackend::OSC52:
        case ClipboardBackend::Stdout:
        default:
            return {};
    }
}

} // namespace smo
