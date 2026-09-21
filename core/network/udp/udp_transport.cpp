#include "udp_transport.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace smo::network::udp {

    // ===========================================================================
    // UdpSession
    // ===========================================================================

    UdpSession::UdpSession(int fd, Endpoint remote, bool owns_fd)
        : fd_(fd), remote_(std::move(remote)), owns_fd_(owns_fd), open_(true)
    {
    }

    UdpSession::~UdpSession() noexcept
    {
        if (open_)
            close();
    }

    Result<void> UdpSession::send(BytesView data)
    {
        if (!open_)
        {
            return SMO_ERR_TRANSPORT(303, Error, NoRetry, None, "UDP session closed");
        }

        struct sockaddr_in addr
        {
        };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(remote_.port);
        if (inet_pton(AF_INET, remote_.host.c_str(), &addr.sin_addr) != 1)
        {
            return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "invalid remote host");
        }

        ssize_t sent =
            ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (sent < 0)
        {
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "UDP send failed");
        }
        return {};
    }

    Result<Bytes> UdpSession::recv(size_t max_bytes)
    {
        if (!open_)
        {
            return SMO_ERR_TRANSPORT(303, Error, NoRetry, None, "UDP session closed");
        }

        // Datagram pulled off the listener fd by accept(); deliver it first.
        if (!pending_.empty())
        {
            Bytes out = std::move(pending_);
            pending_.clear();
            if (max_bytes < out.size())
                out.resize(max_bytes);
            return out;
        }

        Bytes buf(max_bytes);
        struct sockaddr_in peer
        {
        };
        socklen_t addrlen = sizeof(peer);
        ssize_t n = ::recvfrom(fd_, buf.data(), max_bytes, 0, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
        if (n < 0)
        {
            return SMO_ERR_TRANSPORT(305, Error, RetrySafe, Reconnect, "UDP recv failed");
        }
        buf.resize(static_cast<size_t>(n));
        return buf;
    }

    Result<void> UdpSession::close()
    {
        if (!open_)
            return {};
        open_ = false;
        if (owns_fd_)
            ::close(fd_);
        return {};
    }

    Endpoint UdpSession::remote_endpoint() const
    {
        return remote_;
    }

    bool UdpSession::is_open() const
    {
        return open_;
    }

    // ===========================================================================
    // UdpListener
    // ===========================================================================

    UdpListener::UdpListener(int fd, Endpoint local) : fd_(fd), local_(std::move(local)) {}

    UdpListener::~UdpListener() noexcept
    {
        if (fd_ >= 0)
            close();
    }

    Result<std::unique_ptr<TransportSession>> UdpListener::accept()
    {
        // UDP is connectionless: accept pulls the next pending datagram off the
        // bound fd (consuming it) and returns a session that carries that
        // datagram for the caller's first recv(). The session borrows the
        // listener fd (owns_fd=false), so close() must not close the listener.

        char buf[65536];
        struct sockaddr_in peer
        {
        };
        socklen_t addrlen = sizeof(peer);

        ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "no pending UDP data");
            }
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "UDP accept failed");
        }

        Endpoint remote_ep;
        remote_ep.scheme = "udp";
        remote_ep.host = inet_ntoa(peer.sin_addr);
        remote_ep.port = ntohs(peer.sin_port);

        std::unique_ptr<UdpSession> session(new UdpSession(fd_, remote_ep, /*owns_fd=*/false));
        session->pending_.assign(buf, buf + static_cast<size_t>(n));
        return std::unique_ptr<TransportSession>(std::move(session));
    }

    Result<void> UdpListener::close()
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
        return {};
    }

    Endpoint UdpListener::local_endpoint() const
    {
        return local_;
    }

    Result<void> UdpListener::send_to(const Endpoint& remote, BytesView data) const
    {
        if (fd_ < 0)
        {
            return SMO_ERR_TRANSPORT(303, Error, NoRetry, None, "UDP listener closed");
        }

        struct sockaddr_in addr
        {
        };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(remote.port);
        if (inet_pton(AF_INET, remote.host.c_str(), &addr.sin_addr) != 1)
        {
            return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "invalid remote host");
        }

        ssize_t sent =
            ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (sent < 0)
        {
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "UDP send failed");
        }
        return {};
    }

    // ===========================================================================
    // UdpTransport
    // ===========================================================================

    Result<ListenerPtr> UdpTransport::listen(const Endpoint& ep)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            return SMO_ERR_TRANSPORT(306, Error, NoRetry, RestartFSM, "failed to create UDP socket");
        }

        // Set non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        // Reuse address
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr
        {
        };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ep.port);

        if (ep.host.empty() || ep.host == "0.0.0.0" || ep.host == "*")
        {
            addr.sin_addr.s_addr = INADDR_ANY;
        }
        else
        {
            if (inet_pton(AF_INET, ep.host.c_str(), &addr.sin_addr) != 1)
            {
                ::close(fd);
                return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "invalid bind address");
            }
        }

        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            ::close(fd);
            return SMO_ERR_TRANSPORT(307, Error, NoRetry, RestartFSM, "UDP bind failed");
        }

        Endpoint local = ep;
        local.host = "0.0.0.0";

        return ListenerPtr(new UdpListener(fd, local));
    }

    Result<SessionPtr> UdpTransport::connect(const Endpoint& ep)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            return SMO_ERR_TRANSPORT(306, Error, NoRetry, RestartFSM, "failed to create UDP socket");
        }

        struct sockaddr_in addr
        {
        };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ep.port);

        if (inet_pton(AF_INET, ep.host.c_str(), &addr.sin_addr) != 1)
        {
            ::close(fd);
            return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "invalid remote address");
        }

        // Connect the UDP socket (sets default destination)
        if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            ::close(fd);
            return SMO_ERR_TRANSPORT(300, Error, RetryBackoff, Reconnect, "UDP connect failed");
        }

        Endpoint remote;
        remote.scheme = "udp";
        remote.host = ep.host;
        remote.port = ep.port;

        return SessionPtr(new UdpSession(fd, remote));
    }

} // namespace smo::network::udp