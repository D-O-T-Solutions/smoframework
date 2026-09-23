#include <core/network/connection_manager.hpp>

#include <core/runtime/structured_logger.hpp>

namespace { auto& LOG = smo::runtime::global_logger(); }

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>

namespace smo::network
{
    // =========================================================================
    // ConnectionManager implementation — Phase 2
    // -------------------------------------------------------------------------
    // The accept loop that used to live inline in the NodeRuntime accept block
    // (node_runtime.cpp ~1760–1818) now lives here:
    //   1. accept_() — one non-blocking accept attempt
    //   2. parse remote string → smo::Endpoint (host[:port], default_port
    //      fallback when the remote string carries no port)
    //   3. secure path (config_.server_cert_blob non-empty) ⇒ PQ AEAD handshake
    //      hook; plain path ⇒ legacy dispatch hook. Each hook owns+closes the
    //      session, so ConnectionManager stays agnostic to crypto/identity/
    //      membership — all of which the composition root injects through the
    //      hooks rather than through this class's members.
    // =========================================================================
    ConnectionManager::ConnectionManager(Config config, AcceptFn accept, Hook on_secure)
        : config_(std::move(config)),
          accept_(std::move(accept)),
          on_secure_(std::move(on_secure))
    {
    }



    // One non-blocking accept attempt. Returns true if a session was accepted
    // (and handed to the plain or secure hook); false if nothing was waiting
    // (the caller should sleep ~10ms and retry).
    bool ConnectionManager::accept_once()
    {
        if (stop_requested())
            return false; // stop❨ed: no more accepts

        auto accept_res = accept_();
        if (!accept_res)
            return false; // nothing waiting

        auto& session = accept_res.value();
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

        // P0-S6: Always require SecureSession with cert + sig (no plain/legacy path)
        // Capability Epoch (C1.3): pass current_epoch for revocation checking
        auto res = on_secure_(session, remote_ep);
        if (!res)
        {
            LOG.warn("secure dispatch failed: " + res.error().message + " from " + remote_str);
        }
        return true;
    }

    void ConnectionManager::request_stop()
    {
        stop_requested_.store(true);
    }

bool ConnectionManager::stop_requested() const
{
    return stop_requested_.load();
}

ConnectionManager::~ConnectionManager() = default;

} // namespace smo::network
