#pragma once

#include <core/errors/error.hpp>              // smo::Result
#include <core/transport/transport.hpp>
#include <core/types.hpp>  // smo::Bytes       // smo::SessionPtr, smo::Endpoint, smo::TransportSession

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace smo::network
{
    // =========================================================================
    // ConnectionManager — accept-loop owner (Phase 2)
    // -------------------------------------------------------------------------
    // Owns the poll/accept/remote-parse/close machinery that previously lived
    // inline in the NodeRuntime accept block. The composition root injects:
    //   • accept_     — non-blocking accept() → smo::SessionPtr
    //   • on_plain_   — legacy dispatch hook (SessionPtr + parsed remote); it
    //                   owns & closes the session after dispatch.
    //   • on_secure_  — PQ hook (SessionPtr + parsed remote); it builds the
    //                   SecureSession (fd := release_fd), runs the PQ handshake
    //                   and packet-dispatch. Crypto/identity/membership live in
    //                   NodeRuntime; ConnectionManager only moves the bytes.
    // =========================================================================
    class ConnectionManager
    {
    public:
        struct Config
        {
            uint16_t default_port = 7777; // fallback when remote string lacks :port
            smo::Bytes server_cert_blob;   // required for PQ handshake
            smo::Bytes server_signing_key; // required for PQ handshake
            smo::Bytes root_public_key;    // required for PQ handshake
            std::string mesh_id;            // required for PQ handshake
            uint64_t current_epoch = 1;     // Capability Epoch for revocation (C1.3)
        };

        using AcceptFn = std::function<smo::Result<smo::SessionPtr>()>;
        using Hook     = std::function<smo::Result<void>(smo::SessionPtr&,
                                                         const smo::Endpoint&)>;

        ConnectionManager(Config config, AcceptFn accept, Hook on_secure);
        ~ConnectionManager();

        ConnectionManager(const ConnectionManager&) = delete;
        ConnectionManager& operator=(const ConnectionManager&) = delete;
        ConnectionManager(ConnectionManager&&) noexcept;
        ConnectionManager& operator=(ConnectionManager&&) noexcept;

        // One non-blocking accept attempt. Returns true if a session was
        // accepted (and dispatched or closed); false if nothing was waiting
        // (the caller should sleep ~10ms and retry).
        bool accept_once();

        void request_stop();
        bool stop_requested() const;

    private:
        Config config_;
        AcceptFn accept_;
        Hook on_plain_;
        Hook on_secure_;
        std::atomic<bool> stop_requested_{false};
    };
} // namespace smo::network
