#pragma once

#include "../certificate/certificate.hpp"
#include "../crypto/impl.hpp"
#include "../crypto/kdf/argon2id.hpp"
#include "../crypto/recovery_crypto.hpp"
#include "../errors/error.hpp"
#include "../types.hpp"
#include "root_session.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace smo::genesis {

    struct UnlockedKeypair
    {
        Bytes public_key;
        Bytes secret_key;
    };

    struct RecoveryPackage
    {
        std::string mesh_id;
        std::string root_public_key;
        Bytes root_keypair_encrypted;         // Versioned RecoveryDomain envelope (Argon2id + AES-256-GCM)
        uint32_t manifest_revision = 1;
        uint32_t manifest_schema = 1;
        std::string genesis_manifest_json;
        uint64_t created_at = 0;

        // Recovery domain parameters locked by SPEC §7.8 / DISCUSSION_0046 §17.9.
        smo::kdf::Argon2idParams recovery_params;

        Result<Bytes> serialize() const;
        static Result<RecoveryPackage> deserialize(BytesView data);

        // Verify passphrase by attempting to open the recovery envelope (GCM tag).
        // Uses the dedicated RecoveryCryptoProvider — NOT the mesh suite hash.
        bool verify_passphrase(const std::string& passphrase) const;

        // Unlock: verify passphrase + version check, decrypt keypair, return RootSession.
        // The RootSession wraps a SignerContext (software backend by default);
        // call RootSession::destroy() or let it go out of scope to zeroize
        // key material inside the context.
        // Needs signer to construct the SignerContext for the decrypted key.
        Result<RootSession> unlock(const std::string& passphrase, const SignerImpl& signer, RngRef& rng) const;

        // Decrypt only the raw keypair (no SignerContext). Used by authority tooling
        // (e.g. `smo-admin sign`) to load the root/authority keypair from a genesis mesh.
        Result<UnlockedKeypair> unlock_keypair(const std::string& passphrase) const;
    };

    struct EmergencyRecoveryToken
    {
        Bytes token_blob;          // Root-signed recovery authorization
        std::string authorized_by; // Root NodeID
        uint64_t created_at = 0;
        uint64_t expires_at = 0;
        uint32_t target_epoch = 0;

        bool is_valid(uint64_t now_ns) const { return expires_at == 0 || now_ns <= expires_at; }
    };

} // namespace smo::genesis
