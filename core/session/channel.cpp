#include "channel.hpp"

#include <cstring>
#include <limits>

namespace smo {

namespace {

void write_u64(Bytes& out, uint64_t v)
{
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

void write_u16(Bytes& out, uint16_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

uint64_t read_u64(BytesView& data, size_t& offset)
{
    uint64_t v = 0;
    for (int i = 0; i < 8 && offset < data.size(); ++i)
        v = (v << 8) | data[offset++];
    return v;
}

uint16_t read_u16(BytesView& data, size_t& offset)
{
    uint16_t v = 0;
    for (int i = 0; i < 2 && offset < data.size(); ++i)
        v = static_cast<uint16_t>((v << 8) | data[offset++]);
    return v;
}

} // anonymous namespace

// ===========================================================================
// ChannelState
// ===========================================================================

const char* to_string(ChannelState s) noexcept
{
    switch (s)
    {
    case ChannelState::Closed:
        return "Closed";
    case ChannelState::Opening:
        return "Opening";
    case ChannelState::Open:
        return "Open";
    case ChannelState::Closing:
        return "Closing";
    default:
        return "Unknown";
    }
}

bool is_valid_channel_transition(ChannelState from, ChannelEvent event) noexcept
{
    switch (from)
    {
    case ChannelState::Closed:
        return event == ChannelEvent::FirstData || event == ChannelEvent::ExplicitOpen;

    case ChannelState::Opening:
        return event == ChannelEvent::Close || event == ChannelEvent::IdleTimeout || event == ChannelEvent::Error;

    case ChannelState::Open:
        return event == ChannelEvent::Close || event == ChannelEvent::IdleTimeout || event == ChannelEvent::WindowUpdate || event == ChannelEvent::Error;

    case ChannelState::Closing:
        return event == ChannelEvent::IdleTimeout || event == ChannelEvent::Error;

    default:
        return false;
    }
}

ChannelState apply_channel_transition(ChannelState from, ChannelEvent event) noexcept
{
    if (!is_valid_channel_transition(from, event))
        return from;

    switch (event)
    {
    case ChannelEvent::FirstData:
    case ChannelEvent::ExplicitOpen:
        return ChannelState::Open;
    case ChannelEvent::Close:
        return ChannelState::Closing;
    case ChannelEvent::IdleTimeout:
    case ChannelEvent::Error:
        return ChannelState::Closed;
    case ChannelEvent::WindowUpdate:
        return from;
    default:
        return from;
    }
}

// ===========================================================================
// Channel
// ===========================================================================

Result<Channel> Channel::create(uint16_t channel_id, SessionId session_id, int64_t now_ns,
                                uint64_t window_size, uint64_t idle_timeout_ns)
{
    Channel ch;
    ch.channel_id_ = channel_id;
    ch.session_id_ = session_id;
    ch.state_ = ChannelState::Open; // Lazy creation goes directly to Open
    ch.flow_control_.window_size = window_size;
    ch.flow_control_.window_remaining = window_size;
    ch.opened_at_ = now_ns;
    ch.last_activity_at_ = now_ns;
    ch.idle_timeout_ns_ = idle_timeout_ns;
    return ch;
}

bool Channel::is_idle(int64_t now_ns) const noexcept
{
    if (state_ == ChannelState::Closed)
        return true;
    return (now_ns - last_activity_at_) >= static_cast<int64_t>(idle_timeout_ns_);
}

Result<void> Channel::on_event(ChannelEvent event, int64_t now_ns) noexcept
{
    if (!is_valid_channel_transition(state_, event))
    {
        return SMO_ERR_SESSION(520, Error, NoRetry, None,
                                "invalid channel state transition: " + std::string(to_string(state_)) + " + " + std::to_string(static_cast<uint8_t>(event)));
    }

    state_ = apply_channel_transition(state_, event);
    last_activity_at_ = now_ns;

    if (state_ == ChannelState::Closed)
    {
        opened_at_ = now_ns;
    }

    return {};
}

Bytes Channel::serialize() const
{
    Bytes out;
    write_u16(out, channel_id_);

    // SessionId (16 bytes)
    out.insert(out.end(), session_id_.bytes.begin(), session_id_.bytes.end());

    // State
    out.push_back(static_cast<uint8_t>(state_));

    // Flow control
    write_u64(out, flow_control_.window_size);
    write_u64(out, flow_control_.window_remaining);

    // Timestamps
    write_u64(out, static_cast<uint64_t>(opened_at_));
    write_u64(out, static_cast<uint64_t>(last_activity_at_));
    write_u64(out, idle_timeout_ns_);

    return out;
}

Result<Channel> Channel::deserialize(BytesView data)
{
    Channel ch;
    size_t off = 0;

    if (off + 2 > data.size())
    {
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated channel_id");
    }
    ch.channel_id_ = read_u16(data, off);

    if (off + 16 > data.size())
    {
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated session_id");
    }
    std::memcpy(ch.session_id_.bytes.data(), data.data() + off, 16);
    off += 16;

    if (off >= data.size())
    {
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated state");
    }
    ch.state_ = static_cast<ChannelState>(data[off++]);

    if (off + 8 > data.size())
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated window_size");
    ch.flow_control_.window_size = read_u64(data, off);

    if (off + 8 > data.size())
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated window_remaining");
    ch.flow_control_.window_remaining = read_u64(data, off);

    if (off + 8 > data.size())
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated opened_at");
    ch.opened_at_ = static_cast<int64_t>(read_u64(data, off));

    if (off + 8 > data.size())
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated last_activity_at");
    ch.last_activity_at_ = static_cast<int64_t>(read_u64(data, off));

    if (off + 8 > data.size())
        return SMO_ERR_SESSION(521, Error, NoRetry, None, "truncated idle_timeout_ns");
    ch.idle_timeout_ns_ = read_u64(data, off);

    return ch;
}

} // namespace smo