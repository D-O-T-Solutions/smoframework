#pragma once

#include "../certificate/certificate.hpp"
#include "../crypto/impl.hpp"
#include "../crypto/kdf/argon2id.hpp"
#include "../crypto/recovery_crypto.hpp"
#include "../crypto/shamir.hpp"
#include "../crypto/signer/ed25519_provider.hpp"
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

    // Versioned RecoveryPackage formats
    // v1: Single encrypted envelope (Argon2id + AES-256-GCM) — existing format
    // v2: M-of-N Shamir shares, each encrypted with Argon2id + AES-256-GCM per shareholder

    struct RecoveryPackageV1
    {
        std::string mesh_id;
        std::string root_public_key;
        Bytes root_keypair_encrypted;         // Versioned RecoveryDomain envelope (Argon2id + AES-256-GCM)
        uint32_t manifest_revision = 1;
        uint32_t manifest_schema = 1;
        std::string genesis_manifest_json;
        uint64_t created_at = 0;

        smo::kdf::Argon2idParams recovery_params;

        Result<Bytes> serialize() const;
        static Result<RecoveryPackageV1> deserialize(BytesView data);

        bool verify_passphrase(const std::string& passphrase) const;
        Result<RootSession> unlock(const std::string& passphrase, const SignerImpl& signer, RngRef& rng) const;
        Result<UnlockedKeypair> unlock_keypair(const std::string& passphrase) const;
    };

    // Shamir-encrypted share for a single shareholder
    struct ShamirSharePackage
    {
        uint8_t shareholder_index;        // 1..N (matches Shamir x-coordinate)
        Bytes encrypted_share;            // Versioned RecoveryDomain envelope containing 32-byte share
        smo::kdf::Argon2idParams kdf_params; // Per-shareholder Argon2id params (can vary)

        Result<Bytes> serialize() const;
        static Result<ShamirSharePackage> deserialize(BytesView data);

        // Verify shareholder passphrase and decrypt the share
        Result<crypto::ShamirShare> unlock_share(const std::string& passphrase) const;
    };

    // RecoveryPackage v2: M-of-N Shamir Secret Sharing
    struct RecoveryPackageV2
    {
        static constexpr uint8_t kVersion = 2;

        std::string mesh_id;
        std::string root_public_key;
        uint32_t manifest_revision = 1;
        uint32_t manifest_schema = 2;     // Schema version 2 = Shamir SSS
        std::string genesis_manifest_json;
        uint64_t created_at = 0;

        uint8_t threshold = 0;            // M (minimum shares to recover)
        uint8_t total_shares = 0;         // N (total shares generated)
        std::vector<ShamirSharePackage> shares; // N share packages

        // Global KDF params (used as default if share doesn't specify)
        smo::kdf::Argon2idParams default_kdf_params;

        Result<Bytes> serialize() const;
        static Result<RecoveryPackageV2> deserialize(BytesView data);

        // Verify passphrase for a specific shareholder index
        Result<crypto::ShamirShare> verify_and_unlock_share(uint8_t shareholder_index, const std::string& passphrase) const;

        // Recover root keypair from M shareholder passphrases
        // passphrases: vector of (shareholder_index, passphrase) pairs, size >= threshold
        Result<UnlockedKeypair> recover(const std::vector<std::pair<uint8_t, std::string>>& passphrases) const;

        // Create a v2 package from a root keypair (split + encrypt)
        static Result<RecoveryPackageV2> create(const std::string& mesh_id,
                                                 const UnlockedKeypair& keypair,
                                                 uint8_t threshold, uint8_t total_shares,
                                                 const smo::kdf::Argon2idParams& default_kdf_params,
                                                 const std::vector<std::string>& shareholder_passphrases,
                                                 RngRef& rng);
    };

    // Legacy alias for backward compatibility
    using RecoveryPackage = RecoveryPackageV1;

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
