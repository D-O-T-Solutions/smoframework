#include "framing.hpp"

#include <cstring>
#include <unistd.h>

namespace smo {

    void frame_write(BytesView payload, uint8_t flags, Bytes& out)
    {
        FrameHeader hdr;
        hdr.magic = 0x534D4F01;
        hdr.payload_len = static_cast<uint32_t>(payload.size());
        hdr.flags = flags;

        out.resize(sizeof(hdr) + payload.size());
        std::memcpy(out.data(), &hdr, sizeof(hdr));
        if (!payload.empty())
        {
            std::memcpy(out.data() + sizeof(hdr), payload.data(), payload.size());
        }
    }

    size_t frame_read(BytesView buf, FrameHeader& out_header, BytesView& out_payload)
    {
        if (buf.size() < sizeof(FrameHeader))
        {
            return 0;
        }

        FrameHeader hdr;
        std::memcpy(&hdr, buf.data(), sizeof(hdr));

        if (hdr.magic != 0x534D4F01)
        {
            return 0;
        }

        size_t total = sizeof(hdr) + hdr.payload_len;
        if (buf.size() < total)
        {
            return 0;
        }

        out_header = hdr;
        out_payload = buf.subspan(sizeof(hdr), hdr.payload_len);
        return total;
    }

    // ── Version handshake helpers ───────────────────────────────────────────

    static Result<void> write_all(int fd, const void* data, size_t len)
    {
        const auto* ptr = static_cast<const uint8_t*>(data);
        size_t remaining = len;
        while (remaining > 0)
        {
            ssize_t n = ::write(fd, ptr, remaining);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "write failed during version handshake");
            }
            ptr += n;
            remaining -= static_cast<size_t>(n);
        }
        return {};
    }

    static Result<void> read_all(int fd, void* data, size_t len)
    {
        auto* ptr = static_cast<uint8_t*>(data);
        size_t remaining = len;
        while (remaining > 0)
        {
            ssize_t n = ::read(fd, ptr, remaining);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                return SMO_ERR_TRANSPORT(305, Error, NoRetry, Reconnect, "read failed during version handshake");
            }
            if (n == 0)
            {
                return SMO_ERR_TRANSPORT(303, Error, NoRetry, None, "connection closed during version handshake");
            }
            ptr += n;
            remaining -= static_cast<size_t>(n);
        }
        return {};
    }

    Result<uint32_t> version_handshake_client(int fd)
    {
        // Client sends supported version
        uint32_t client_ver = kTransportVersion;
        SMO_TRY(write_all(fd, &client_ver, sizeof(client_ver)));

        // Read server response
        uint32_t server_ver = 0;
        SMO_TRY(read_all(fd, &server_ver, sizeof(server_ver)));

        if (server_ver == 0)
        {
            return SMO_ERR_TRANSPORT(312, Error, NoRetry, Reconnect, "server rejected version negotiation");
        }
        if (server_ver > kTransportVersion)
        {
            return SMO_ERR_TRANSPORT(313, Warn, NoRetry, Reenroll, "version mismatch: server ver > client ver");
        }

        return server_ver;
    }

    Result<uint32_t> version_handshake_server(int fd)
    {
        // Read client version
        uint32_t client_ver = 0;
        SMO_TRY(read_all(fd, &client_ver, sizeof(client_ver)));

        uint32_t negotiated = 0;
        if (client_ver >= 1 && client_ver <= kTransportVersion)
        {
            negotiated = client_ver;
        }

        // Send negotiated version (0 = reject)
        SMO_TRY(write_all(fd, &negotiated, sizeof(negotiated)));

        if (negotiated == 0)
        {
            return SMO_ERR_TRANSPORT(312, Error, NoRetry, Reconnect, "client version not supported");
        }

        return negotiated;
    }

    // ── Length-prefixed field framing (join domain, RFC 0007 AMEND-5) ──────

    Result<void> write_field(int fd, BytesView data)
    {
        uint8_t len_hdr[2];
        len_hdr[0] = static_cast<uint8_t>((data.size() >> 8) & 0xFF);
        len_hdr[1] = static_cast<uint8_t>(data.size() & 0xFF);
        SMO_TRY(write_all(fd, len_hdr, 2));
        if (!data.empty())
        {
            return write_all(fd, data.data(), data.size());
        }
        return {};
    }

    Result<Bytes> read_field(int fd)
    {
        uint8_t len_hdr[2];
        SMO_TRY(read_all(fd, len_hdr, 2));
        uint16_t sz = (static_cast<uint16_t>(len_hdr[0]) << 8) | static_cast<uint16_t>(len_hdr[1]);
        Bytes buf(sz);
        if (sz > 0)
        {
            SMO_TRY(read_all(fd, buf.data(), sz));
        }
        return buf;
    }

} // namespace smo
