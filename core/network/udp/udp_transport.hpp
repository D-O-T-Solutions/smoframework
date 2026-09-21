#pragma once

#include <core/transport/transport.hpp>
#include <core/types.hpp>

#include <memory>
#include <string>

namespace smo::network::udp {

    class UdpSession final : public TransportSession
    {
    public:
        // owns_fd=false: the session borrows a shared listener fd (datagram
        // accept() path); close() must NOT close the underlying listener.
        explicit UdpSession(int fd, Endpoint remote, bool owns_fd = true);
        ~UdpSession() noexcept override;

        UdpSession(const UdpSession&) = delete;
        UdpSession& operator=(const UdpSession&) = delete;

        friend class UdpListener;

        Result<void> send(BytesView data) override;
        Result<Bytes> recv(size_t max_bytes) override;
        Result<void> close() override;
        Endpoint remote_endpoint() const override;
        bool is_open() const override;

    private:
        int fd_;
        Endpoint remote_;
        bool open_ = true;
        bool owns_fd_ = true;
        Bytes pending_; // datagram consumed by the listener accept() path; drained on first recv()
    };

    class UdpListener final : public TransportListener
    {
    public:
        UdpListener(int fd, Endpoint local);
        ~UdpListener() noexcept override;

        UdpListener(const UdpListener&) = delete;
        UdpListener& operator=(const UdpListener&) = delete;

        Result<std::unique_ptr<TransportSession>> accept() override;
        Result<void> close() override;
        Endpoint local_endpoint() const override;

        // Send a datagram from the already-bound socket (no ephemeral socket).
        Result<void> send_to(const Endpoint& remote, BytesView data) const;

    private:
        int fd_;
        Endpoint local_;
    };

    class UdpTransport final : public Transport
    {
    public:
        UdpTransport() = default;

        std::string_view name() const override { return "udp"; }

        Result<ListenerPtr> listen(const Endpoint& ep) override;
        Result<SessionPtr> connect(const Endpoint& ep) override;
    };

} // namespace smo::network::udp