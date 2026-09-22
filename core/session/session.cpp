#include "session.hpp"

#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>

namespace smo {

    // ===========================================================================
    // Helpers — big-endian read/write
    // ===========================================================================

    namespace {

        void write_u64(Bytes& out, uint64_t v)
        {
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>(v >> (i * 8)));
        }

        void write_u32(Bytes& out, uint32_t v)
        {
            for (int i = 3; i >= 0; --i)
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

        uint32_t read_u32(BytesView& data, size_t& offset)
        {
            uint32_t v = 0;
            for (int i = 0; i < 4 && offset < data.size(); ++i)
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
    // SessionState
    // ===========================================================================

    const char* to_string(SessionState s) noexcept
    {
        switch (s)
        {
        case SessionState::Closed:
            return "Closed";
        case SessionState::Handshake:
            return "Handshake";
        case SessionState::Established:
            return "Established";
        case SessionState::Active:
            return "Active";
        case SessionState::Renewing:
            return "Renewing";
        default:
            return "Unknown";
        }
    }

    // ===========================================================================
    // FSM transitions
    // ===========================================================================

    bool is_valid_transition(SessionState from, SessionEvent event) noexcept
    {
        switch (from)
        {
        case SessionState::Closed:
            return event == SessionEvent::OpenRequest;

        case SessionState::Handshake:
            return event == SessionEvent::Established || event == SessionEvent::Close ||
                   event == SessionEvent::Timeout || event == SessionEvent::Error;

        case SessionState::Established:
            return event == SessionEvent::Activate || event == SessionEvent::Renew || event == SessionEvent::Close ||
                   event == SessionEvent::Timeout || event == SessionEvent::Error;

        case SessionState::Active:
            return event == SessionEvent::CompleteContract || event == SessionEvent::Close ||
                   event == SessionEvent::Error;

        case SessionState::Renewing:
            return event == SessionEvent::Established || event == SessionEvent::Close ||
                   event == SessionEvent::Timeout || event == SessionEvent::Error;

        default:
            return false;
        }
    }

    SessionState apply_transition(SessionState from, SessionEvent event) noexcept
    {
        if (!is_valid_transition(from, event))
            return from;

        switch (event)
        {
        case SessionEvent::OpenRequest:
            return SessionState::Handshake;
        case SessionEvent::Established:
            return SessionState::Established;
        case SessionEvent::Activate:
            return SessionState::Active;
        case SessionEvent::CompleteContract:
            return SessionState::Established;
        case SessionEvent::Renew:
            return SessionState::Renewing;
        case SessionEvent::Close:
        case SessionEvent::Timeout:
        case SessionEvent::Error:
            return SessionState::Closed;
        default:
            return from;
        }
    }

    // ===========================================================================
    // Session
    // ===========================================================================

    Result<Session> Session::create(SessionId id, NodeID peer_id, Certificate peer_cert, CapabilitySet capabilities,
                                    int64_t now, uint64_t ttl_ns)
    {
        if (ttl_ns > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "TTL exceeds int64_t range");
        }
        Session s;
        s.id_ = id;
        s.state_ = SessionState::Handshake;
        s.peer_id_ = peer_id;
        s.peer_cert_ = std::move(peer_cert);
        s.capabilities_ = capabilities;
        s.created_at_ = now;
        s.expires_at_ = now + static_cast<int64_t>(ttl_ns);
        s.last_active_ = now;
        s.security_state_.session_id = id;
        s.security_state_.epoch = 0;
        s.security_state_.tx_sequence = 0;
        s.security_state_.rx_epoch = 0;
        return s;
    }

    Result<void> Session::on_event(SessionEvent event, int64_t now) noexcept
    {
        if (!is_valid_transition(state_, event))
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "invalid session state transition");
        }

        state_ = apply_transition(state_, event);
        last_active_ = now;

        if (state_ == SessionState::Closed)
        {
            expires_at_ = now;
        }

        return {};
    }

    Result<void> Session::renew(int64_t now, uint64_t ttl_ns) noexcept
    {
        if (state_ != SessionState::Established && state_ != SessionState::Active)
        {
            return SMO_ERR_SESSION(505, Warn, RetrySafe, Reconnect, "renew only valid in Established/Active state");
        }
        if (ttl_ns > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "TTL exceeds int64_t range");
        }
        expires_at_ = now + static_cast<int64_t>(ttl_ns);
        last_active_ = now;
        return {};
    }

    Bytes Session::serialize() const
    {
        Bytes out;
        out.push_back(static_cast<uint8_t>(state_));
        out.insert(out.end(), id_.bytes.begin(), id_.bytes.end());
        out.insert(out.end(), peer_id_.value.begin(), peer_id_.value.end());

        // Capability bitset as bytes
        size_t cap_bytes = (capabilities_.size() + 7) / 8;
        for (size_t i = 0; i < cap_bytes; ++i)
        {
            uint8_t byte = 0;
            for (size_t j = 0; j < 8 && (i * 8 + j) < capabilities_.size(); ++j)
            {
                if (capabilities_[i * 8 + j])
                    byte |= static_cast<uint8_t>(1 << j);
            }
            out.push_back(byte);
        }

        write_u64(out, static_cast<uint64_t>(created_at_));
        write_u64(out, static_cast<uint64_t>(expires_at_));
        write_u64(out, static_cast<uint64_t>(last_active_));

        Bytes cert_ser = peer_cert_.serialize();
        write_u32(out, static_cast<uint32_t>(cert_ser.size()));
        out.insert(out.end(), cert_ser.begin(), cert_ser.end());

        // SessionSecurityState (P5)
        out.insert(out.end(), security_state_.session_id.bytes.begin(), security_state_.session_id.bytes.end());
        write_u64(out, security_state_.epoch);
        write_u64(out, security_state_.tx_sequence);
        write_u64(out, security_state_.rx_epoch);
        write_u64(out, security_state_.rx_window.highest());
        write_u64(out, security_state_.rx_window.bitmap()); // Need accessor

        return out;
    }

    Result<Session> Session::deserialize(BytesView data)
    {
        Session s;
        size_t off = 0;

        if (off >= data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated session data");
        }
        s.state_ = static_cast<SessionState>(data[off++]);

        if (off + 16 > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated session id");
        }
        std::memcpy(s.id_.bytes.data(), data.data() + off, 16);
        off += 16;

        if (off + 32 > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated peer id");
        }
        std::memcpy(s.peer_id_.value.data(), data.data() + off, 32);
        off += 32;

        // Capability bitset
        size_t cap_bytes = (s.capabilities_.size() + 7) / 8;
        if (off + cap_bytes > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated capabilities");
        }
        for (size_t i = 0; i < cap_bytes && off < data.size(); ++i)
        {
            for (size_t j = 0; j < 8 && (i * 8 + j) < s.capabilities_.size(); ++j)
            {
                if (data[off] & (1 << j))
                    s.capabilities_.set(i * 8 + j);
            }
            off++;
        }

        s.created_at_ = static_cast<int64_t>(read_u64(data, off));
        s.expires_at_ = static_cast<int64_t>(read_u64(data, off));
        s.last_active_ = static_cast<int64_t>(read_u64(data, off));

        uint32_t cert_len = read_u32(data, off);
        if (off + cert_len > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated certificate");
        }
        auto cert_data = data.subspan(off, cert_len);
        off += cert_len;

        auto cert = Certificate::deserialize(cert_data);
        if (!cert)
            return std::move(cert.error());
        s.peer_cert_ = std::move(cert.value());

        // SessionSecurityState (P5)
        if (off + 16 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state session_id");
        std::memcpy(s.security_state_.session_id.bytes.data(), data.data() + off, 16);
        off += 16;
        if (off + 8 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state epoch");
        s.security_state_.epoch = read_u64(data, off);
        if (off + 8 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state tx_sequence");
        s.security_state_.tx_sequence = read_u64(data, off);
        if (off + 8 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state rx_epoch");
        s.security_state_.rx_epoch = read_u64(data, off);
        if (off + 8 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state rx_highest");
        uint64_t rx_highest = read_u64(data, off);
        if (off + 8 > data.size())
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated security state rx_bitmap");
        uint64_t rx_bitmap = read_u64(data, off);
        s.security_state_.rx_window.restore(rx_highest, rx_bitmap);

        return s;
    }

    // ===========================================================================
    // SessionManager
    // ===========================================================================

    uint64_t SessionManager::to_key(const SessionId& id)
    {
        uint64_t key = 0;
        std::memcpy(&key, id.bytes.data(), sizeof(key));
        return key;
    }

    Result<Session*> SessionManager::open(Session session)
    {
        // CRL check: if CRL is configured and session has a cert fingerprint,
        // verify the certificate is not revoked.
        if (crl_ && !session.cert_fingerprint().empty())
        {
            auto revoked = crl_->is_revoked(session.cert_fingerprint());
            if (!revoked)
            {
                if (telemetry_)
                    telemetry_->increment_counter("smo_sessions_open_total", "result=crl_check_failed");
                return SMO_ERR_SESSION(507, Error, NoRetry, Reconnect, "CRL check failed: " + revoked.error().message);
            }
            if (revoked.value())
            {
                if (telemetry_)
                    telemetry_->increment_counter("smo_sessions_open_total", "result=revoked");
                return SMO_ERR_SESSION(508, Error, NoRetry, Reconnect, "session rejected: certificate is revoked");
            }
        }

        auto key = to_key(session.id());
        if (sessions_.find(key) != sessions_.end())
        {
            if (telemetry_)
                telemetry_->increment_counter("smo_sessions_open_total", "result=duplicate");
            return SMO_ERR_SESSION(504, Warn, NoRetry, None, "session already exists");
        }
        auto [it, inserted] = sessions_.emplace(key, std::move(session));
        if (!inserted)
        {
            if (telemetry_)
                telemetry_->increment_counter("smo_sessions_open_total", "result=insert_failed");
            return SMO_ERR_SESSION(504, Warn, NoRetry, None, "failed to insert session");
        }
        if (telemetry_)
        {
            telemetry_->increment_counter("smo_sessions_open_total", "result=success");
            telemetry_->set_gauge("smo_sessions_active", static_cast<double>(sessions_.size()), "");
        }
        return &it->second;
    }

    Session* SessionManager::lookup(const SessionId& id)
    {
        auto key = to_key(id);
        auto it = sessions_.find(key);
        if (it == sessions_.end())
            return nullptr;
        return &it->second;
    }

    size_t SessionManager::invalidate(const NodeID& peer_id)
    {
        size_t count = 0;
        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (it->second.peer_id() == peer_id)
            {
                it = sessions_.erase(it);
                ++count;
            }
            else
            {
                ++it;
            }
        }
        if (telemetry_ && count > 0)
        {
            telemetry_->increment_counter("smo_sessions_invalidated_total", "count=" + std::to_string(count));
            telemetry_->set_gauge("smo_sessions_active", static_cast<double>(sessions_.size()), "");
        }
        return count;
    }

    Result<void> SessionManager::close(const SessionId& id, int64_t now)
    {
        auto* session = lookup(id);
        if (!session)
        {
            if (telemetry_)
                telemetry_->increment_counter("smo_sessions_close_total", "result=not_found");
            return SMO_ERR_SESSION(501, Info, RetrySafe, Reconnect, "session not found");
        }
        auto state_before = session->state();
        auto result = session->on_event(SessionEvent::Close, now);
        if (result && telemetry_)
        {
            telemetry_->increment_counter("smo_sessions_close_total", "result=success,state_before=" + std::string(to_string(state_before)));
            telemetry_->set_gauge("smo_sessions_active", static_cast<double>(sessions_.size()), "");
        }
        else if (telemetry_)
        {
            telemetry_->increment_counter("smo_sessions_close_total", "result=failed");
        }
        return result;
    }

    Result<void> SessionManager::transition(const SessionId& id, SessionEvent event, int64_t now)
    {
        auto* session = lookup(id);
        if (!session)
        {
            if (telemetry_)
                telemetry_->increment_counter("smo_sessions_transition_total", "result=not_found,event=" + std::to_string(static_cast<int>(event)));
            return SMO_ERR_SESSION(501, Info, RetrySafe, Reconnect, "session not found");
        }
        auto state_before = session->state();
        auto result = session->on_event(event, now);
        if (result && telemetry_)
        {
            telemetry_->increment_counter("smo_sessions_transition_total", "result=success,from=" + std::string(to_string(state_before)) + ",to=" + std::string(to_string(session->state())));
        }
        else if (telemetry_)
        {
            telemetry_->increment_counter("smo_sessions_transition_total", "result=failed,event=" + std::to_string(static_cast<int>(event)));
        }
        return result;
    }

    void SessionManager::tick(int64_t now)
    {
        size_t expired_count = 0;
        for (auto& [key, session] : sessions_)
        {
            if (session.is_valid_at(now))
                continue;
            session.on_event(SessionEvent::Timeout, now);
            expired_count++;
        }
        if (telemetry_ && expired_count > 0)
        {
            telemetry_->increment_counter("smo_sessions_expired_total", "count=" + std::to_string(expired_count));
            telemetry_->set_gauge("smo_sessions_active", static_cast<double>(sessions_.size()), "");
        }
    }

    void SessionManager::collect_garbage()
    {
        size_t collected = 0;
        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (it->second.state() == SessionState::Closed)
            {
                it = sessions_.erase(it);
                collected++;
            }
            else
            {
                ++it;
            }
        }
        if (telemetry_ && collected > 0)
        {
            telemetry_->increment_counter("smo_sessions_garbage_collected_total", "count=" + std::to_string(collected));
            telemetry_->set_gauge("smo_sessions_active", static_cast<double>(sessions_.size()), "");
        }
    }

    Bytes SessionManager::serialize_all() const
    {
        Bytes out;
        write_u32(out, static_cast<uint32_t>(sessions_.size()));
        for (const auto& [key, session] : sessions_)
        {
            Bytes ser = session.serialize();
            write_u32(out, static_cast<uint32_t>(ser.size()));
            out.insert(out.end(), ser.begin(), ser.end());
        }
        return out;
    }

    // ===========================================================================
    // SessionManager::persist / recover — RFC 0014 §6 crash recovery
    // ===========================================================================

    Result<void> SessionManager::persist(const std::string& path) const
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "cannot open session store for write: " + path);
        }
        Bytes ser = serialize_all();
        out.write(reinterpret_cast<const char*>(ser.data()), static_cast<std::streamsize>(ser.size()));
        if (!out)
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "failed writing session store: " + path);
        }
        return {};
    }

    Result<size_t> SessionManager::recover(const std::string& path, int64_t now)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in)
        {
            // No store on disk yet — nothing to recover.
            return 0;
        }
        in.seekg(0, std::ios::end);
        std::streamsize sz = in.tellg();
        in.seekg(0, std::ios::beg);
        if (sz <= 0)
        {
            return 0;
        }
        Bytes data(static_cast<size_t>(sz));
        in.read(reinterpret_cast<char*>(data.data()), sz);
        if (!in)
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "failed reading session store: " + path);
        }

        size_t off = 0;
        BytesView data_view(data);
        uint32_t count = read_u32(data_view, off);
        size_t recovered = 0;
        size_t orphans = 0;
        for (uint32_t i = 0; i < count; ++i)
        {
            uint32_t len = read_u32(data_view, off);
            if (off + len > data.size())
                break;
            auto res = Session::deserialize(BytesView(data).subspan(off, len));
            off += len;
            if (!res)
                continue;

            Session persisted = std::move(res.value());
            // RFC 0014 §6: sessions ACTIVE at crash time own contracts that are
            // now orphans; they cannot resume. Everyone is closed deterministically.
            if (persisted.state() == SessionState::Active)
            {
                persisted.on_event(SessionEvent::Close, now);
                ++orphans;
            }
            else if (persisted.state() == SessionState::Established || persisted.state() == SessionState::Renewing)
            {
                // Graceful close: no contract was in flight.
                persisted.on_event(SessionEvent::Close, now);
            }
            else
            {
                // Handshake / Closed — drop silently.
                continue;
            }

            auto key = to_key(persisted.id());
            if (sessions_.find(key) == sessions_.end())
            {
                sessions_.emplace(key, std::move(persisted));
                ++recovered;
            }
        }

        std::printf("[smo-node] SessionManager: recovered %zu sessions from %s (%zu orphaned ACTIVE contracts)\n",
                    recovered, path.c_str(), orphans);
        return recovered;
    }

    // ===========================================================================
    // SessionOpenMsg
    // ===========================================================================

    Bytes SessionOpenMsg::serialize() const
    {
        Bytes out;
        // nonce (32 bytes)
        size_t nonce_len = nonce.size() < 32 ? nonce.size() : 32;
        for (size_t i = 0; i < 32; ++i)
        {
            out.push_back(i < nonce_len ? nonce[i] : 0);
        }
        // signature (64 bytes)
        size_t sig_len = signature.size() < 64 ? signature.size() : 64;
        for (size_t i = 0; i < 64; ++i)
        {
            out.push_back(i < sig_len ? signature[i] : 0);
        }
        // cert data
        write_u32(out, static_cast<uint32_t>(cert_data.size()));
        out.insert(out.end(), cert_data.begin(), cert_data.end());
        return out;
    }

    Result<SessionOpenMsg> SessionOpenMsg::deserialize(BytesView data)
    {
        SessionOpenMsg msg;
        size_t off = 0;

        if (off + 32 > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated nonce in SessionOpenMsg");
        }
        msg.nonce = Bytes(data.begin() + static_cast<ptrdiff_t>(off), data.begin() + static_cast<ptrdiff_t>(off + 32));
        off += 32;

        if (off + 64 > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated signature in SessionOpenMsg");
        }
        msg.signature =
            Bytes(data.begin() + static_cast<ptrdiff_t>(off), data.begin() + static_cast<ptrdiff_t>(off + 64));
        off += 64;

        uint32_t cert_len = read_u32(data, off);
        if (off + cert_len > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated cert data in SessionOpenMsg");
        }
        msg.cert_data =
            Bytes(data.begin() + static_cast<ptrdiff_t>(off), data.begin() + static_cast<ptrdiff_t>(off + cert_len));
        off += cert_len;

        return msg;
    }

    // ===========================================================================
    // SessionCloseMsg
    // ===========================================================================

    Bytes SessionCloseMsg::serialize() const
    {
        Bytes out;
        out.push_back(reason);
        size_t sig_len = signature.size() < 64 ? signature.size() : 64;
        for (size_t i = 0; i < 64; ++i)
        {
            out.push_back(i < sig_len ? signature[i] : 0);
        }
        return out;
    }

    Result<SessionCloseMsg> SessionCloseMsg::deserialize(BytesView data)
    {
        SessionCloseMsg msg;
        size_t off = 0;

        if (off >= data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated reason in SessionCloseMsg");
        }
        msg.reason = data[off++];

        if (off + 64 > data.size())
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated signature in SessionCloseMsg");
        }
        msg.signature =
            Bytes(data.begin() + static_cast<ptrdiff_t>(off), data.begin() + static_cast<ptrdiff_t>(off + 64));
        return msg;
    }

    // EventBus listener for RecoveryApproved events
    // Invalidates all sessions for the revoked node
    void SessionManager::on_recovery_approved(const runtime::Event& ev)
    {
        // Parse JSON payload from event details
        // Expected: "CertificateRevocation proposal approved: {fingerprint, node_id_hex, reason, epoch}"
        std::string payload = ev.details;
        size_t brace_pos = payload.find('{');
        if (brace_pos == std::string::npos)
            return;

        std::string json_str = payload.substr(brace_pos);

        // Simple JSON parsing
        auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
            std::string search = "\"" + key + "\":\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos)
                return "";
            pos += search.length();
            size_t end = json.find('"', pos);
            if (end == std::string::npos)
                return "";
            return json.substr(pos, end - pos);
        };

        std::string node_id_hex = extract_field(json_str, "node_id_hex");
        if (node_id_hex.empty())
            return;

        // Convert hex string to NodeID
        if (node_id_hex.size() != 64)
            return; // 32 bytes = 64 hex chars
        NodeID node_id;
        for (size_t i = 0; i < 32 && i * 2 + 1 < node_id_hex.size(); ++i)
        {
            unsigned int byte = 0;
            std::istringstream iss(node_id_hex.substr(i * 2, 2));
            iss >> std::hex >> byte;
            node_id.value[i] = static_cast<uint8_t>(byte);
        }

        // Invalidate all sessions for this node
        size_t count = invalidate(node_id);
        if (count > 0)
        {
            std::printf("[smo-node] SessionManager: invalidated %zu sessions for node %s\n", count,
                        node_id_hex.c_str());
        }
    }

} // namespace smo
