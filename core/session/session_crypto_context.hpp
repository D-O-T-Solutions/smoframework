#pragma once

#include "../types.hpp"
#include "session_id.hpp"

namespace smo {

    // ── PacketTxKey / PacketRxKey ────────────────────────────────────────
    // Opaque, move-only packet crypto capabilities (B2a). Directional by
    // type so orientation cannot be mixed up at compile time:
    //   client.packet_tx_key() matches server.packet_rx_key()
    //   server.packet_tx_key() matches client.packet_rx_key()
    //
    // The key material is private; there is intentionally NO raw getter.
    // packet_crypto borrows the capability and operates through it.
    class PacketRxKey;

    class PacketTxKey
    {
    public:
        PacketTxKey() = default;
        PacketTxKey(PacketTxKey&&) noexcept = default;
        PacketTxKey& operator=(PacketTxKey&&) noexcept = default;
        PacketTxKey(const PacketTxKey&) = delete;
        PacketTxKey& operator=(const PacketTxKey&) = delete;

        bool valid() const noexcept { return !material_.empty(); }

        // Constant-time equality check (B2b) — for orientation verification.
        bool matches(const PacketRxKey& other) const noexcept;

    private:
        explicit PacketTxKey(Bytes material) : material_(std::move(material)) {}

        Bytes material_;

        friend class SessionCryptoContext;
        friend class PacketRxKey; // symmetric matches()
    };

    class PacketRxKey
    {
    public:
        PacketRxKey() = default;
        PacketRxKey(PacketRxKey&&) noexcept = default;
        PacketRxKey& operator=(PacketRxKey&&) noexcept = default;
        PacketRxKey(const PacketRxKey&) = delete;
        PacketRxKey& operator=(const PacketRxKey&) = delete;

        bool valid() const noexcept { return !material_.empty(); }

        // Constant-time equality check (symmetric helper).
        bool matches(const PacketTxKey& other) const noexcept;

    private:
        explicit PacketRxKey(Bytes material) : material_(std::move(material)) {}

        Bytes material_;

        friend class SessionCryptoContext;
        friend class PacketTxKey;
    };

    // ── SessionCryptoContext ─────────────────────────────────────────────
    // Owns the handshake-derived session identity and packet crypto
    // capability (B2c: session layer). Created exactly once per established
    // session; packet layer borrows it and never re-derives keys.
    //
    // B2d: SessionSecurityState holds state only — this context owns secrets.
    class SessionCryptoContext
    {
    public:
        SessionCryptoContext() = default;
        SessionCryptoContext(SessionCryptoContext&&) noexcept = default;
        SessionCryptoContext& operator=(SessionCryptoContext&&) noexcept = default;
        SessionCryptoContext(const SessionCryptoContext&) = delete;
        SessionCryptoContext& operator=(const SessionCryptoContext&) = delete;

        // Build from the final-direction keys (already swapped on the server).
        // Copies the key bytes into opaque capabilities.
        static SessionCryptoContext create(SessionId id, BytesView tx_key, BytesView rx_key);

        bool valid() const noexcept { return tx_key_.valid() && rx_key_.valid(); }

        const SessionId& session_id() const noexcept { return session_id_; }

        // Borrow only — keys are move-only opaque capabilities.
        const PacketTxKey& packet_tx_key() const noexcept { return tx_key_; }
        const PacketRxKey& packet_rx_key() const noexcept { return rx_key_; }

    private:
        SessionId session_id_{};
        PacketTxKey tx_key_{};
        PacketRxKey rx_key_{};
    };

} // namespace smo
