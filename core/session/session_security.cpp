#include "session_security.hpp"

namespace smo {

    bool ReplayWindow::is_acceptable(uint64_t sequence) const noexcept
    {
        // Sequence 0 is reserved (RFC 0019: zero nonces are rejected).
        if (sequence == 0)
            return false;

        // New high-water mark — always acceptable.
        if (sequence > highest_)
            return true;

        const uint64_t diff = highest_ - sequence;
        // diff == 0 => the high-water mark itself, already seen.
        // diff >= window => older than the window, stale.
        if (diff == 0 || diff >= kWindowBits)
            return false;

        return (bitmap_ & (uint64_t{1} << diff)) == 0;
    }

    bool ReplayWindow::commit(uint64_t sequence) noexcept
    {
        if (!is_acceptable(sequence))
            return false;

        if (sequence > highest_)
        {
            const uint64_t shift = sequence - highest_;
            if (shift >= kWindowBits)
                bitmap_ = 0;
            else
                bitmap_ = (bitmap_ << shift) | (uint64_t{1} << shift);
            highest_ = sequence;
        }
        else
        {
            const uint64_t diff = highest_ - sequence;
            bitmap_ |= (uint64_t{1} << diff);
        }
        return true;
    }

    void ReplayWindow::reset() noexcept
    {
        highest_ = 0;
        bitmap_ = 0;
    }

    void SessionSecurityState::rekey() noexcept
    {
        ++epoch;
        tx_sequence = 0;
        rx_epoch = epoch;
        rx_window.reset();
    }

} // namespace smo
