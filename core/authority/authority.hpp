#pragma once

#include "../crypto/impl.hpp"
#include "../crypto/signer_context.hpp"
#include "../certificate/certificate.hpp"
#include "../identity/identity.hpp"
#include "registry.hpp"

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <optional>

namespace smo::authority {

    // ---------------------------------------------------------------------------
    // AuthorityKeyRotation — key rotation metadata and state
    // ---------------------------------------------------------------------------
    struct AuthorityKeyRotation
    {
        uint64_t epoch = 1;                    // Current authority epoch
        Bytes previous_authority_pubkey;       // Previous authority public key
        Bytes current_authority_pubkey;        // Current authority public key
        int64_t rotated_at = 0;                // Unix timestamp of rotation
        std::string rotation_reason;           // "scheduled", "compromise", "hsm_migration"
        bool rotation_pending = false;         // True if rotation in progress
    };

    // ---------------------------------------------------------------------------
    // IntermediateCA — intermediate certificate authority record
    // ---------------------------------------------------------------------------
    struct IntermediateCA
    {
        std::string ca_id;                     // Unique identifier
        Bytes subject_pubkey;                  // Intermediate CA public key
        Bytes issuer_pubkey;                   // Issuer public key (root or another intermediate)
        Certificate certificate;               // Full certificate
        uint64_t epoch = 1;                    // Authority epoch when created
        int64_t created_at = 0;                // Unix timestamp
        int64_t expires_at = 0;                // Unix timestamp
        std::string status;                    // "active", "revoked", "expired"
    };

    // ---------------------------------------------------------------------------
    // MeshAuthority — manages Root/Authority keys, CSR signing, certificate issuance
    //
    // Lifecycle:
    //   1. Mesh create → Authority.create_root() → generates Root keypair
    //   2. Root signs Authority certificate → Authority keypair created
    //   3. Root key exported (RecoveryPackage) → deleted from runtime (NEVER CIRCULATES)
    //   4. Authority key stays online for daily signing (HSM/remote signer supported)
    //   5. Key rotation: re-key authority, re-issue certs, increment epoch
    // ---------------------------------------------------------------------------
    class MeshAuthority
    {
    public:
        struct Config
        {
            std::string mesh_id;
            std::string data_dir;      // Path to mesh data directory
            std::string registry_path; // Path to node_registry.db
            bool hsm_enabled = false;  // Use HSM/remote signer for authority key
        };

        MeshAuthority();
        ~MeshAuthority();

        MeshAuthority(const MeshAuthority&) = delete;
        MeshAuthority& operator=(const MeshAuthority&) = delete;
        MeshAuthority(MeshAuthority&&) = default;
        MeshAuthority& operator=(MeshAuthority&&) = default;

        // ── Initialization ──────────────────────────────────────────

        // Initialize with crypto provider
        Result<void> init(const CryptoProvider& crypto, RngRef& rng);

        // Open existing authority (load keys from disk)
        Result<void> open(const Config& config);

        // ── Root / Authority Key Management ──────────────────────────

        // DEPRECATED — use the genesis flow instead.
        //   smo genesis create  (Stage 0 + Stage 1)
        //
        // Create mesh: generate Root keypair + first Authority keypair
        // root_pubkey_out: output hex of root public key
        // recovery_out: output AES-256-GCM encrypted recovery package
        [[deprecated("Use genesis flow: smo genesis create")]] Result<void>
        create_mesh_keys(const Config& config, const CryptoProvider& crypto, RngRef& rng, std::string& root_pubkey_out);

        // Load authority secret key via HSM/remote signer context
        // The root key NEVER circulates in runtime — it's only in RecoveryPackage
        Result<void> load_authority_key(const Config& config,
                                        std::unique_ptr<crypto::SignerContext> signer_ctx = nullptr);

        // Get current authority signer context (for HSM/remote signing)
        crypto::SignerContext* authority_signer() const;

        // ── Key Rotation (C7.3) ──────────────────────────────────────

        // Initiate authority key rotation
        // Generates new authority keypair, signs new authority cert with root (offline)
        // Returns new authority public key hex for out-of-band root signing
        Result<std::string> initiate_key_rotation(const std::string& reason = "scheduled",
                                                  RngRef* rng = nullptr);

        // Complete key rotation after root signs new authority certificate
        // root_signed_auth_cert: root-signed authority certificate (from offline CA)
        // Re-issues all active node certificates under new authority key
        Result<void> complete_key_rotation(const Certificate& root_signed_auth_cert,
                                           const std::string& recovery_passphrase);

        // Get current rotation state
        AuthorityKeyRotation get_rotation_state() const;

        // ── Bootstrap Signing (Root during Genesis/Bootstrap) ────────

        struct BootstrapSignRequest
        {
            Bytes csr_blob; // Serialized CSR from joining node
            std::string mesh_id;
            std::string slot_token; // Bootstrap Slot token for verification
            uint32_t slot_index;
        };

        // Sign a CSR during bootstrap. Validates slot token first, then
        // issues a certificate. Called by Root during Stage 1.
        // Returns: slot-signed Certificate
        Result<Certificate> sign_bootstrap_csr(const BootstrapSignRequest& req);

        // ── CSR Signing (Authority runtime) ──────────────────────────

        // Sign a CSR: validate, issue certificate, log to registry
        // csr_blob: raw serialized CSR bytes
        // mesh_id: target mesh
        // Returns: serialized Certificate
        Result<Certificate> sign_csr(BytesView csr_blob, const std::string& mesh_id);

        // Sign arbitrary data with the authority's private key (via HSM/software)
        // Used for bootstrap tickets, manifest deltas, etc.
        // Returns: signature bytes
        Result<Bytes> sign_data(BytesView data, RngRef& rng);

        // ── Certificate Operations ───────────────────────────────────

        // Verify a certificate chain (supports intermediate CAs)
        Result<void> verify_chain(const CertificateChain& chain) const;

        // Revoke a certificate by fingerprint
        Result<void> revoke_certificate(const std::string& cert_fingerprint, const std::string& reason);

        // ── Intermediate CA Management (C7.4) ────────────────────────

        // Add an intermediate CA (certificate must be signed by root or another intermediate)
        Result<void> add_intermediate_ca(const IntermediateCA& ca);

        // List all intermediate CAs
        Result<std::vector<IntermediateCA>> list_intermediate_cas() const;

        // Get intermediate CA by ID
        Result<std::optional<IntermediateCA>> get_intermediate_ca(const std::string& ca_id) const;

        // Revoke an intermediate CA
        Result<void> revoke_intermediate_ca(const std::string& ca_id, const std::string& reason);

        // ── Accessors ────────────────────────────────────────────────

        NodeRegistry& registry() { return *registry_; }
        const NodeRegistry& registry() const { return *registry_; }
        bool is_initialized() const { return initialized_; }
        std::string mesh_id() const { return config_.mesh_id; }
        uint64_t current_epoch() const;

        // ── Public Key Accessors (join-token / handshake verification) ──

        // Authority public key (loaded from disk / generated at mesh create)
        const Bytes& authority_public_key() const;

        // Root public key (only loaded if root.cert is present in data_dir)
        const Bytes& root_public_key() const;

        // Get RNG reference for signing operations
        RngRef& rng();

        // Get authority key metadata
        const crypto::SignerMetadata& authority_key_metadata() const;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
        Config config_;
        bool initialized_ = false;
        std::unique_ptr<NodeRegistry> registry_;
    };

} // namespace smo::authority