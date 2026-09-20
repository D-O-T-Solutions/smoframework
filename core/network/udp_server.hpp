#pragma once

#include <core/errors/error.hpp>              // smo::Result
#include <core/transport/transport.hpp>       // smo::SessionPtr, smo::Endpoint
#include <core/types.hpp>                     // smo::Bytes

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace smo::network
{

    // =========================================================================
    // UdpServer — UDP datagram read-loop owner (Phase 3)
    // -------------------------------------------------------------------------
    // Owns the recvfrom/dispatch machinery that previously lived inline in the
    // NodeRuntime run loop. The composition root injects:
    //   • recv_fn     — non-blocking recvfrom → smo::Result<smo::SessionPtr>
    //   • on_datagram — discovery dispatch hook (SessionPtr + parsed remote);
    //                   it owns & closes the session after dispatch.
    // =========================================================================
    class UdpServer
    {
    public:
        struct Config
        {
            uint16_t default_port = 7777; // fallback when remote string lacks :port
            size_t max_datagram_size = 8192;
        };

        using RecvFn = std::function<smo::Result<smo::SessionPtr>()>;
        using Hook   = std::function<smo::Result<void>(smo::SessionPtr&,
                                                       const smo::Endpoint&)>;

        UdpServer(Config config, RecvFn recv_fn, Hook on_datagram);
        ~UdpServer();

        UdpServer(const UdpServer&) = delete;
        UdpServer& operator=(const UdpServer&) = delete;
        UdpServer(UdpServer&&) noexcept;
        UdpServer& operator=(UdpServer&&) noexcept;

        // One non-blocking recv attempt. Returns true if a datagram was
        // received (and dispatched); false if nothing was waiting
        // (the caller should sleep ~10ms and retry).
        bool recv_once();

        void request_stop();
        bool stop_requested() const;

    private:
        Config config_;
        RecvFn recv_fn_;
        Hook on_datagram_;
        std::atomic<bool> stop_requested_{false};
    };

} // namespace smo::network