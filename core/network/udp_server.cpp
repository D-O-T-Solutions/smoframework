#include <core/network/udp_server.hpp>

#include <core/runtime/structured_logger.hpp>

namespace { auto& LOG = smo::runtime::global_logger(); }

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>

namespace smo::network
{

    // =========================================================================
    // UdpServer implementation — Phase 3
    // -------------------------------------------------------------------------
    // The UDP datagram loop that used to live inline in the NodeRuntime run loop
    // (node_runtime.cpp ~1733–1751) now lives here:
    //   1. recv_fn() — one non-blocking recvfrom attempt
    //   2. parse remote string → smo::Endpoint (host[:port], default_port
    //      fallback when the remote string carries no port)
    //   3. dispatch via injected on_datagram hook (DiscoveryEngine path)
    // =========================================================================
    UdpServer::UdpServer(Config config, RecvFn recv_fn, Hook on_datagram)
        : config_(std::move(config)),
          recv_fn_(std::move(recv_fn)),
          on_datagram_(std::move(on_datagram))
    {
    }



    // One non-blocking recv attempt. Returns true if a datagram was received
    // (and handed to the datagram hook); false if nothing was waiting
    // (the caller should sleep ~10ms and retry).
    bool UdpServer::recv_once()
    {
        if (stop_requested())
            return false; // stopped: no more receives

        auto recv_res = recv_fn_();
        if (!recv_res)
            return false; // nothing waiting

        auto& session = recv_res.value();
        if (!session)
            return false; // transient: nothing usable

        const std::string remote_str = session->remote_endpoint().to_string();
        const auto colon = remote_str.rfind(':');

        smo::Endpoint remote_ep;
        if (colon != std::string::npos)
        {
            remote_ep.host = remote_str.substr(0, colon);
            remote_ep.port =
                static_cast<uint16_t>(std::strtoul(remote_str.substr(colon + 1).c_str(), nullptr, 10));
        }
        else
        {
            remote_ep.host = remote_str;
            remote_ep.port = static_cast<uint16_t>(config_.default_port);
        }

        // Dispatch datagram via injected hook (owns & closes the session)
        auto res = on_datagram_(session, remote_ep);
        if (!res)
        {
            LOG.warn("udp datagram dispatch failed: " + res.error().message + " from " + remote_str);
        }
        return true;
    }

    void UdpServer::request_stop()
    {
        stop_requested_.store(true);
    }

    bool UdpServer::stop_requested() const
    {
        return stop_requested_.load();
    }

} // namespace smo::network