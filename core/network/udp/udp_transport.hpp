#pragma once

#include <core/transport/transport.hpp>
#include <core/types.hpp>

#include <memory>
#include <string>

namespace smo::network::udp {

class UdpSession final : public TransportSession {
public:
    explicit UdpSession(int fd, Endpoint remote);
    ~UdpSession() noexcept override;

    UdpSession(const UdpSession&) = delete;
    UdpSession& operator=(const UdpSession&) = delete;

    Result<void> send(BytesView data) override;
    Result<Bytes> recv(size_t max_bytes) override;
    Result<void> close() override;
    Endpoint remote_endpoint() const override;
    bool is_open() const override;

private:
    int fd_;
    Endpoint remote_;
    bool open_ = true;
};

class UdpListener final : public TransportListener {
public:
    UdpListener(int fd, Endpoint local);
    ~UdpListener() noexcept override;

    UdpListener(const UdpListener&) = delete;
    UdpListener& operator=(const UdpListener&) = delete;

    Result<std::unique_ptr<TransportSession>> accept() override;
    Result<void> close() override;
    Endpoint local_endpoint() const override;

private:
    int fd_;
    Endpoint local_;
};

class UdpTransport final : public Transport {
public:
    UdpTransport() = default;

    std::string_view name() const override { return "udp"; }

    Result<ListenerPtr> listen(const Endpoint& ep) override;
    Result<SessionPtr> connect(const Endpoint& ep) override;
};

} // namespace smo::network::udp