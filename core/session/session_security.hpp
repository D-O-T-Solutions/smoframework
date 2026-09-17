#pragma once

#include "../types.hpp"
#include "session_id.hpp"

#include <array>
#include <cstdint>

namespace smo {

    // ── ReplayWindow ─────────────────────────────────────────────────────
    // 64-bit sliding replay window for one direction of one session epoch.
    // Representation: bit j (1..63) => sequence (highest_ - j) already seen.
    // highest_ itself is implicitly seen.
    //
    // RFC 0019 AMEND-4: replay protection via session_id + epoch + sequence
    // + replay window. Check is_acceptable() first, then commit() ONLY after
    // AEAD authentication succeeds (never advance state on a bad packet).
    class ReplayWindow
    {
    public:
        static constexpr uint64_t kWindowBits = 64;

        // Precheck only — MUST NOT mutate.
        bool is_acceptable(uint64_t sequence) const noexcept;

        // Mark sequence as seen. Returns false for replay/stale values.
        bool commit(uint64_t sequence) noexcept;

        uint64_t highest() const noexcept { return highest_; }

        uint64_t bitmap() const noexcept { return bitmap_; }

        // Restore replay window state (for crash recovery).
        void restore(uint64_t highest, uint64_t bitmap) noexcept
        {
            highest_ = highest;
            bitmap_ = bitmap;
        }

        // Reset for a new epoch (rekey / restart).
        void reset() noexcept;

    private:
        uint64_t highest_{0};
        uint64_t bitmap_{0};
    };

    // ── SessionSecurityState ─────────────────────────────────────────────
    // Per-session security state (Q8: session layer). Owns the monotonic TX
    // sequence and the RX replay window for the current epoch.
    // session_id is created once at session establishment (B3a) and consumed
    // by the packet layer; packet code never derives it again.
    //
    // B2d: this struct holds NO key material. Packet crypto capability is
    // owned by SessionCryptoContext; state here is state-only.
    struct SessionSecurityState
    {
        SessionId session_id{}; // 128-bit, set once (canonical type)
        uint64_t epoch{0};
        uint64_t tx_sequence{0}; // monotonic, starts at 1 on first send
        uint64_t rx_epoch{0};
        ReplayWindow rx_window{};

        // Q11 invariant: rekey => epoch++, TX sequence reset, RX window reset.
        void rekey() noexcept;
    };

} // namespace smo
