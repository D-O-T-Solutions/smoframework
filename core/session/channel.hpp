#pragma once

#include "session_id.hpp"
#include "../errors/error.hpp"
#include "../types.hpp"

#include <cstdint>
#include <chrono>

namespace smo {

// Channel error codes (520-535)
namespace ChannelErrc {
    inline constexpr ErrorCode InvalidState(ErrorCategory::Session, 520, Severity::Error, RetryClass::NoRetry,
                                             Recovery::None);
    inline constexpr ErrorCode NotFound(ErrorCategory::Session, 521, Severity::Warn, RetryClass::RetrySafe,
                                         Recovery::None);
    inline constexpr ErrorCode WindowExceeded(ErrorCategory::Session, 522, Severity::Warn, RetryClass::RetryBackoff,
                                               Recovery::None);
    inline constexpr ErrorCode IdleTimeout(ErrorCategory::Session, 523, Severity::Info, RetryClass::RetrySafe,
                                            Recovery::None);
    inline constexpr ErrorCode DuplicateId(ErrorCategory::Session, 524, Severity::Warn, RetryClass::NoRetry,
                                            Recovery::None);
    inline constexpr ErrorCode FlowControlBlocked(ErrorCategory::Session, 525, Severity::Warn, RetryClass::RetryBackoff,
                                                   Recovery::None);
} // namespace ChannelErrc

// ChannelState — 4-state FSM per RFC 0042 §2.4
enum class ChannelState : uint8_t
{
    Closed = 0,
    Opening = 1,
    Open = 2,
    Closing = 3,
};

const char* to_string(ChannelState s) noexcept;

// ChannelEvent — events that drive channel FSM transitions
enum class ChannelEvent : uint8_t
{
    FirstData = 0,       // First packet arrives on this channel (lazy open)
    ExplicitOpen = 1,    // CHANNEL_OPEN frame received (optional)
    Close = 2,           // CHANNEL_CLOSE/FIN/CANCEL received or local close
    IdleTimeout = 3,     // No activity for idle_timeout_ns
    WindowUpdate = 4,    // WINDOW_UPDATE received
    Error = 5,           // Protocol error
};

// Valid transitions per RFC 0042
bool is_valid_channel_transition(ChannelState from, ChannelEvent event) noexcept;
ChannelState apply_channel_transition(ChannelState from, ChannelEvent event) noexcept;

// Flow control per channel (RFC 0042 §2.3)
struct ChannelFlowControl
{
    uint64_t window_size = 65536;      // Initial window (64KB default)
    uint64_t window_remaining = 65536; // Current available window

    bool can_send(uint64_t size) const noexcept { return size <= window_remaining; }
    void on_send(uint64_t size) noexcept { window_remaining -= size; }
    void on_window_update(uint64_t increment) noexcept { window_remaining += increment; }
    void reset_window(uint64_t new_size) noexcept { window_size = window_remaining = new_size; }
};

// Channel — logical stream within a session (RFC 0042 §2.4)
class Channel
{
public:
    Channel() = default;

    // Create a new channel (lazy creation on first data)
    static Result<Channel> create(uint16_t channel_id, SessionId session_id, int64_t now_ns,
                                  uint64_t window_size = 65536,
                                  uint64_t idle_timeout_ns = 300'000'000'000); // 5 min default

    // Channel ID (unique within session)
    uint16_t channel_id() const noexcept { return channel_id_; }

    // Session this channel belongs to
    const SessionId& session_id() const noexcept { return session_id_; }

    // FSM state
    ChannelState state() const noexcept { return state_; }

    // Flow control
    ChannelFlowControl& flow_control() noexcept { return flow_control_; }
    const ChannelFlowControl& flow_control() const noexcept { return flow_control_; }

    // Timeouts
    int64_t opened_at() const noexcept { return opened_at_; }
    int64_t last_activity_at() const noexcept { return last_activity_at_; }
    uint64_t idle_timeout_ns() const noexcept { return idle_timeout_ns_; }

    // Check if channel is idle (no activity for idle_timeout_ns)
    bool is_idle(int64_t now_ns) const noexcept;

    // Update last activity timestamp
    void touch(int64_t now_ns) noexcept { last_activity_at_ = now_ns; }

    // FSM transition
    Result<void> on_event(ChannelEvent event, int64_t now_ns) noexcept;

    // Serialize for persistence
    Bytes serialize() const;
    static Result<Channel> deserialize(BytesView data);

private:
    uint16_t channel_id_ = 0;
    SessionId session_id_{};
    ChannelState state_ = ChannelState::Closed;
    ChannelFlowControl flow_control_{};
    int64_t opened_at_ = 0;
    int64_t last_activity_at_ = 0;
    uint64_t idle_timeout_ns_ = 300'000'000'000; // 5 min default
};

} // namespace smo