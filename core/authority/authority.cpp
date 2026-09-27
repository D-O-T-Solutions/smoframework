#include "authority.hpp"

#include "../crypto/impl.hpp"
#include "../crypto/recovery_crypto.hpp"
#include "../crypto/kdf/argon2id.hpp"
#include "../certificate/certificate.hpp"
#include "../errors/error.hpp"
#include "../identity/identity.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sqlite3.h>

namespace smo::authority {

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    static Bytes hex_to_bytes(const std::string& hex)
    {
        Bytes out;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            char buf[3] = {hex[i], hex[i + 1], 0};
            out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
        }
        return out;
    }

    static std::string fingerprint(BytesView cert_bytes, const HashImpl& hash)
    {
        auto h = hash.hash(cert_bytes);
        if (!h)
            return "";
        return smo::bytes_to_hex(h.value());
    }

    static int64_t now_ms()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    static int64_t now_ns()
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    // ---------------------------------------------------------------------------
    // MeshAuthority::Impl
    // ---------------------------------------------------------------------------

    class MeshAuthority::Impl
    {
    public:
        const CryptoProvider* crypto_ = nullptr;
        RngRef rng_;

        // Authority keypair (loaded from disk or generated at mesh create)
        Bytes authority_public_key_;
        Bytes authority_secret_key_;

        // Root public key (only stored; private key exported then deleted)
        Bytes root_public_key_;

        // Current mesh epoch
        uint64_t epoch_ = 1;

        // Key rotation state
        AuthorityKeyRotation rotation_state_;

        // HSM/remote signer context (optional)
        std::unique_ptr<crypto::SignerContext> authority_signer_ctx_;

        // Intermediate CAs
        std::vector<IntermediateCA> intermediate_cas_;

        bool has_authority_key() const
        {
            return !authority_public_key_.empty() &&
                   (authority_signer_ctx_ != nullptr || !authority_secret_key_.empty());
        }

        bool has_root_public_key() const { return !root_public_key_.empty(); }

        // Sign a certificate using authority's private key (via HSM or software)
        Result<void> sign_certificate(Certificate& cert, RngRef& rng)
        {
            if (!has_authority_key())
            {
                return SMO_ERR_CERT(210, Critical, NoRetry, ManualIntervention, "authority key not loaded");
            }

            auto body = cert.serialize();

            if (authority_signer_ctx_)
            {
                auto sig = authority_signer_ctx_->sign(body, rng);
                if (!sig)
                    return sig.error();
                cert.signature = std::move(sig.value());
            }
            else
            {
                if (!crypto_->signer.sign)
                {
                    return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "signer has no sign function");
                }
                auto sig = crypto_->signer.sign(body, authority_secret_key_, rng);
                if (!sig)
                    return sig.error();
                cert.signature = std::move(sig.value());
            }
            return {};
        }

        // Issue a new certificate from CSR
        Result<Certificate> issue_certificate(const CertificateSigningRequest& csr, const std::string& mesh_id)
        {
            if (!crypto_->hash.hash)
            {
                return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "no hash function");
            }

            Certificate cert;
            cert.subject_pubkey = csr.new_public_key;
            cert.issuer_pubkey = authority_public_key_;
            cert.mesh_id.assign(mesh_id.begin(), mesh_id.end());
            cert.display_name = csr.display_name;
            cert.role = Role::Member; // Default role
            cert.epoch = epoch_;
            cert.not_before = now_ms() / 1000;
            cert.not_after = cert.not_before + 31536000; // +1 year

            // Sign with authority key
            auto sig_result = sign_certificate(cert, rng_);
            if (!sig_result)
                return sig_result.error();

            // Compute fingerprint
            auto serialized = cert.serialize();
            auto fp = crypto_->hash.hash(serialized);
            if (!fp)
                return fp.error();

            return cert;
        }

        // Load intermediate CAs from registry
        Result<void> load_intermediate_cas()
        {
            // Query from database
            intermediate_cas_.clear();
            if (!registry_)
                return {};

            auto certs = registry_->list_certificates();
            if (!certs)
                return certs.error();

            for (const auto& rec : certs.value())
            {
                if (rec.role == "IntermediateCA" && rec.status == "active")
                {
                    IntermediateCA ca;
                    ca.ca_id = rec.node_id_hex;
                    ca.subject_pubkey = hex_to_bytes(rec.subject_pubkey_hex);
                    ca.issuer_pubkey = hex_to_bytes(rec.issuer_pubkey_hex);
                    ca.epoch = rec.epoch;
                    ca.created_at = rec.issued_at;
                    ca.expires_at = rec.expires_at;
                    ca.status = rec.status;

                    // Load full certificate
                    auto cert_bytes = hex_to_bytes(rec.cert_fingerprint); // fingerprint is hash, need full cert
                    // For now, reconstruct minimal cert
                    ca.certificate.subject_pubkey = ca.subject_pubkey;
                    ca.certificate.issuer_pubkey = ca.issuer_pubkey;
                    ca.certificate.mesh_id.assign(config_.mesh_id.begin(), config_.mesh_id.end());
                    ca.certificate.role = Role::Authority;
                    ca.certificate.epoch = rec.epoch;
                    ca.certificate.not_before = rec.issued_at / 1000;
                    ca.certificate.not_after = rec.expires_at / 1000;

                    intermediate_cas_.push_back(std::move(ca));
                }
            }
            return {};
        }

        Config config_;
        std::unique_ptr<NodeRegistry> registry_;

        // Sign with root key (offline operation - only during genesis/bootstrap)
        // This should NEVER be called during normal runtime - root key never circulates
        Result<Certificate> sign_with_root_key(Certificate& cert, BytesView root_secret_key, RngRef& rng)
        {
            if (!crypto_->signer.sign)
            {
                return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "signer has no sign function");
            }
            auto body = cert.serialize();
            auto sig = crypto_->signer.sign(body, root_secret_key, rng);
            if (!sig)
                return sig.error();
            cert.signature = std::move(sig.value());
            return {};
        }
    };

    // ---------------------------------------------------------------------------
    // MeshAuthority
    // ---------------------------------------------------------------------------

    MeshAuthority::MeshAuthority() : impl_(std::make_unique<Impl>()) {}

    MeshAuthority::~MeshAuthority() = default;

    Result<void> MeshAuthority::init(const CryptoProvider& crypto, RngRef& rng)
    {
        impl_->crypto_ = &crypto;
        impl_->rng_ = rng;
        initialized_ = true;
        return {};
    }

    Result<void> MeshAuthority::open(const Config& config)
    {
        config_ = config;
        impl_->config_ = config;

        // Load authority keys from disk (or use in-memory keys if already initialized)
        std::string pk_path = config.data_dir + "/authority.pub";
        std::string sk_path = config.data_dir + "/authority.sec";

        // Load public key from disk (required)
        std::ifstream pk_file(pk_path, std::ios::binary);
        if (!pk_file)
        {
            return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.pub not found in " + config.data_dir);
        }
        impl_->authority_public_key_ =
            Bytes((std::istreambuf_iterator<char>(pk_file)), std::istreambuf_iterator<char>());

        // Load secret key from disk (encrypted) or use in-memory key if already initialized
        if (impl_->authority_secret_key_.empty() && !impl_->authority_signer_ctx_)
        {
            std::ifstream sk_file(sk_path, std::ios::binary);
            if (!sk_file)
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.sec not found in " + config.data_dir);
            }
            Bytes blob((std::istreambuf_iterator<char>(sk_file)), std::istreambuf_iterator<char>());
            if (blob.empty())
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.sec empty");
            }

            // P0-EX: decrypt with the dedicated RecoveryDomain (Argon2id + AES-256-GCM)
            // via crypto::RecoveryCryptoProvider — the single SMO abstraction for
            // recovery/authority secret material. No EVP_* here (SPEC §7.8, §26.3).
            const char* env_pw = std::getenv("SMO_RECOVERY_PASSPHRASE");
            std::string passphrase = env_pw ? env_pw : "smo-recovery-passphrase";

            BytesView aad(reinterpret_cast<const uint8_t*>(config.mesh_id.data()), config.mesh_id.size());
            auto plaintext_res = smo::crypto::RecoveryCryptoProvider::open(
                BytesView(blob), aad,
                BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
            if (!plaintext_res)
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None,
                                        "Failed to decrypt authority.sec: " + plaintext_res.error().message);
            }
            impl_->authority_secret_key_ = std::move(plaintext_res).value();
        }

        // Load root public key. Two sources:
        //  1. root.cert (created by the legacy create_mesh_keys flow)
        //  2. mesh manifest "root_public_key" (hex) — genesis flow
        {
            std::string root_cert_path = config.data_dir + "/root.cert";
            std::ifstream root_cert_file(root_cert_path, std::ios::binary);
            if (root_cert_file)
            {
                Bytes root_cert_blob((std::istreambuf_iterator<char>(root_cert_file)), std::istreambuf_iterator<char>());
                auto root_cert = Certificate::deserialize(BytesView(root_cert_blob));
                if (root_cert)
                {
                    impl_->root_public_key_ = root_cert.value().subject_pubkey;
                }
            }

            if (impl_->root_public_key_.empty())
            {
                std::string manifest_path = config.data_dir + "/mesh.json";
                std::ifstream mf(manifest_path);
                if (mf)
                {
                    std::string mjson((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
                    auto key_pos = mjson.find("\"root_public_key\"");
                    if (key_pos != std::string::npos)
                    {
                        auto colon = mjson.find(':', key_pos);
                        auto start = colon != std::string::npos ? mjson.find('"', colon + 1) : std::string::npos;
                        auto end = start != std::string::npos ? mjson.find('"', start + 1) : std::string::npos;
                        if (start != std::string::npos && end != std::string::npos)
                        {
                            std::string root_hex = mjson.substr(start + 1, end - start - 1);
                            if (!root_hex.empty())
                            {
                                Bytes root_raw = hex_to_bytes(root_hex);
                                if (!root_raw.empty())
                                {
                                    impl_->root_public_key_ = std::move(root_raw);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Load intermediate CAs
        impl_->load_intermediate_cas();

        // Open registry
        registry_ = std::make_unique<NodeRegistry>();
        auto r = registry_->open(config.registry_path);
        if (!r)
            return r;
        impl_->registry_ = std::move(registry_);

        initialized_ = true;
        return {};
    }

    Result<void> MeshAuthority::load_authority_key(const Config& config,
                                                   std::unique_ptr<crypto::SignerContext> signer_ctx)
    {
        config_ = config;
        impl_->config_ = config;

        // Load public key from disk
        std::string pk_path = config.data_dir + "/authority.pub";
        std::ifstream pk_file(pk_path, std::ios::binary);
        if (!pk_file)
        {
            return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.pub not found in " + config.data_dir);
        }
        impl_->authority_public_key_ =
            Bytes((std::istreambuf_iterator<char>(pk_file)), std::istreambuf_iterator<char>());

        // Use provided HSM/remote signer context
        if (signer_ctx)
        {
            if (!signer_ctx->valid())
            {
                return SMO_ERR_CRYPTO(110, Error, NoRetry, ManualIntervention, "provided SignerContext is invalid");
            }
            impl_->authority_signer_ctx_ = std::move(signer_ctx);
            config_.hsm_enabled = true;
        }
        else
        {
            // Load software key from encrypted file
            std::string sk_path = config.data_dir + "/authority.sec";
            std::ifstream sk_file(sk_path, std::ios::binary);
            if (!sk_file)
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.sec not found in " + config.data_dir);
            }
            Bytes blob((std::istreambuf_iterator<char>(sk_file)), std::istreambuf_iterator<char>());
            if (blob.empty())
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None, "authority.sec empty");
            }

            const char* env_pw = std::getenv("SMO_RECOVERY_PASSPHRASE");
            std::string passphrase = env_pw ? env_pw : "smo-recovery-passphrase";

            BytesView aad(reinterpret_cast<const uint8_t*>(config.mesh_id.data()), config.mesh_id.size());
            auto plaintext_res = smo::crypto::RecoveryCryptoProvider::open(
                BytesView(blob), aad,
                BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
            if (!plaintext_res)
            {
                return SMO_ERR_IDENTITY(101, Error, NoRetry, None,
                                        "Failed to decrypt authority.sec: " + plaintext_res.error().message);
            }
            impl_->authority_secret_key_ = std::move(plaintext_res).value();
            config_.hsm_enabled = false;
        }

        // Load root public key
        {
            std::string root_cert_path = config.data_dir + "/root.cert";
            std::ifstream root_cert_file(root_cert_path, std::ios::binary);
            if (root_cert_file)
            {
                Bytes root_cert_blob((std::istreambuf_iterator<char>(root_cert_file)), std::istreambuf_iterator<char>());
                auto root_cert = Certificate::deserialize(BytesView(root_cert_blob));
                if (root_cert)
                {
                    impl_->root_public_key_ = root_cert.value().subject_pubkey;
                }
            }

            if (impl_->root_public_key_.empty())
            {
                std::string manifest_path = config.data_dir + "/mesh.json";
                std::ifstream mf(manifest_path);
                if (mf)
                {
                    std::string mjson((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
                    auto key_pos = mjson.find("\"root_public_key\"");
                    if (key_pos != std::string::npos)
                    {
                        auto colon = mjson.find(':', key_pos);
                        auto start = colon != std::string::npos ? mjson.find('"', colon + 1) : std::string::npos;
                        auto end = start != std::string::npos ? mjson.find('"', start + 1) : std::string::npos;
                        if (start != std::string::npos && end != std::string::npos)
                        {
                            std::string root_hex = mjson.substr(start + 1, end - start - 1);
                            if (!root_hex.empty())
                            {
                                Bytes root_raw = hex_to_bytes(root_hex);
                                if (!root_raw.empty())
                                {
                                    impl_->root_public_key_ = std::move(root_raw);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Load intermediate CAs
        impl_->load_intermediate_cas();

        // Open registry
        registry_ = std::make_unique<NodeRegistry>();
        auto r = registry_->open(config.registry_path);
        if (!r)
            return r;
        impl_->registry_ = std::move(registry_);

        initialized_ = true;
        return {};
    }

    Result<void> MeshAuthority::create_mesh_keys(const Config& config, const CryptoProvider& crypto, RngRef& rng,
                                                 std::string& root_pubkey_out)
    {
        config_ = config;
        impl_->crypto_ = &crypto;
        impl_->rng_ = rng;
        impl_->config_ = config;

        // 1. Generate Root keypair
        if (!crypto.signer.generate_keypair)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "no keygen function");
        }
        auto root_kp = crypto.signer.generate_keypair(rng);
        if (!root_kp)
            return root_kp.error();

        impl_->root_public_key_ = root_kp.value().public_key;
        root_pubkey_out = smo::bytes_to_hex(impl_->root_public_key_);

        // 2. Generate Authority keypair
        auto auth_kp = crypto.signer.generate_keypair(rng);
        if (!auth_kp)
            return auth_kp.error();

        impl_->authority_public_key_ = auth_kp.value().public_key;
        impl_->authority_secret_key_ = auth_kp.value().secret_key;

        // 3. Create Root-signed Authority certificate
        Certificate root_cert;
        root_cert.subject_pubkey = impl_->root_public_key_;
        root_cert.issuer_pubkey = impl_->root_public_key_; // self-signed
        root_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
        root_cert.display_name = config.mesh_id + "-root";
        root_cert.role = Role::Root;
        root_cert.epoch = 1;
        root_cert.not_before = now_ms() / 1000;
        root_cert.not_after = root_cert.not_before + 31536000 * 10; // 10 years

        // Sign root cert with root key
        {
            auto body = root_cert.serialize();
            auto sig = crypto.signer.sign(body, root_kp.value().secret_key, rng);
            if (!sig)
                return sig.error();
            root_cert.signature = std::move(sig.value());
        }

        // Authority cert signed by root
        Certificate auth_cert;
        auth_cert.subject_pubkey = impl_->authority_public_key_;
        auth_cert.issuer_pubkey = impl_->root_public_key_;
        auth_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
        auth_cert.display_name = config.mesh_id + "-authority";
        auth_cert.role = Role::Authority;
        auth_cert.epoch = 1;
        auth_cert.not_before = now_ms() / 1000;
        auth_cert.not_after = auth_cert.not_before + 31536000; // 1 year

        // Sign authority cert with root key
        {
            auto body = auth_cert.serialize();
            auto sig = crypto.signer.sign(body, root_kp.value().secret_key, rng);
            if (!sig)
                return sig.error();
            auth_cert.signature = std::move(sig.value());
        }

        // 4. Save authority keys to disk
        {
            std::ofstream pk_file(config.data_dir + "/authority.pub", std::ios::binary);
            pk_file.write(reinterpret_cast<const char*>(impl_->authority_public_key_.data()),
                          impl_->authority_public_key_.size());

            // Encrypt the authority secret key with the recovery passphrase
            const char* env_pw = std::getenv("SMO_RECOVERY_PASSPHRASE");
            std::string passphrase = env_pw ? env_pw : "smo-recovery-passphrase";

            kdf::Argon2idParams argon_params; // use defaults
            BytesView aad(reinterpret_cast<const uint8_t*>(config.mesh_id.data()), config.mesh_id.size());

            auto enc_res = crypto::RecoveryCryptoProvider::seal(
                BytesView(impl_->authority_secret_key_.data(), impl_->authority_secret_key_.size()),
                aad,
                BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()),
                argon_params,
                rng);

            if (!enc_res)
            {
                return enc_res.error();
            }

            std::ofstream sk_file(config.data_dir + "/authority.sec", std::ios::binary);
            sk_file.write(reinterpret_cast<const char*>(enc_res.value().data()),
                          enc_res.value().size());
        }

        // 5. Save root cert + authority cert
        {
            auto root_serialized = root_cert.serialize();
            std::ofstream f(config.data_dir + "/root.cert", std::ios::binary);
            f.write(reinterpret_cast<const char*>(root_serialized.data()), root_serialized.size());
        }
        {
            auto auth_serialized = auth_cert.serialize();
            std::ofstream f(config.data_dir + "/authority.cert", std::ios::binary);
            f.write(reinterpret_cast<const char*>(auth_serialized.data()), auth_serialized.size());
        }

        // 6. Root private key: In production, this would be encrypted into
        //    a RecoveryPackage and then securely deleted.
        //    For now, we just don't save it to disk.
        //    TODO: Implement RecoveryPackage (AES-256-GCM)

        // 7. Open registry
        registry_ = std::make_unique<NodeRegistry>();
        auto r = registry_->open(config.registry_path);
        if (!r)
            return r;
        impl_->registry_ = std::move(registry_);

        // 8. Register Authority node itself
        {
            NodeRecord auth_node;
            auth_node.node_id_hex = smo::bytes_to_hex(crypto.hash.hash(impl_->authority_public_key_).value());
            auth_node.display_name = config.mesh_id + "-authority";
            auth_node.mesh_id = config.mesh_id;
            auth_node.role = "Authority";
            auth_node.status = "active";
            auth_node.epoch = 1;
            auth_node.enrolled_at = now_ms();
            auto rr = impl_->registry_->register_node(auth_node);
            if (!rr)
                return rr;
        }

        // 9. Register Root node
        {
            NodeRecord root_node;
            root_node.node_id_hex = smo::bytes_to_hex(crypto.hash.hash(impl_->root_public_key_).value());
            root_node.display_name = config.mesh_id + "-root";
            root_node.mesh_id = config.mesh_id;
            root_node.role = "Root";
            root_node.status = "offline"; // Root is offline
            root_node.epoch = 1;
            root_node.enrolled_at = now_ms();
            auto rr = impl_->registry_->register_node(root_node);
            if (!rr)
                return rr;
        }

        initialized_ = true;
        return {};
    }

    Result<Certificate> MeshAuthority::sign_csr(BytesView csr_blob, const std::string& mesh_id)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (!impl_->crypto_ || !impl_->crypto_->signer.verify)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "crypto not configured");
        }

        // 1. Deserialize CSR
        auto csr = CertificateSigningRequest::deserialize(csr_blob);
        if (!csr)
            return csr.error();

        // 2. Verify CSR signature
        auto valid = csr.value().verify(impl_->crypto_->signer, csr.value().new_public_key);
        if (!valid)
            return valid.error();
        if (!valid.value())
        {
            return SMO_ERR_CERT(209, Alert, NoRetry, None, "CSR signature invalid");
        }

        // 3. Validate and normalize display name
        auto name_valid = validate_display_name(csr.value().display_name);
        if (!name_valid)
            return name_valid.error();
        std::string normalized = normalize_display_name(csr.value().display_name);

        // 4. Issue certificate (subject_pubkey = ML-DSA key from CSR)
        auto cert = impl_->issue_certificate(csr.value(), mesh_id);
        if (!cert)
            return cert.error();

        // 5. Atomic enrollment: node + cert + alias in one SQLite transaction
        if (impl_->registry_)
        {
            auto serialized = cert.value().serialize();
            auto fp = impl_->crypto_->hash.hash(serialized);
            if (!fp)
                return fp.error();
            std::string fp_hex = smo::bytes_to_hex(fp.value());

            // Compute node_id = Blake3(public_key)
            auto node_id_result = node_id_from_public_key(csr.value().new_public_key, impl_->crypto_->hash);
            if (!node_id_result)
                return node_id_result.error();
            std::string node_id_hex = node_id_result.value().to_string();

            auto enroll = impl_->registry_->enroll_node(node_id_hex, normalized, mesh_id, "Member", fp_hex,
                                                        smo::bytes_to_hex(impl_->authority_public_key_),
                                                        smo::bytes_to_hex(csr.value().new_public_key), impl_->epoch_, now_ms(),
                                                        now_ms() + 31536000000LL // +1 year
            );
            if (!enroll)
            {
                // enroll_node() maps SQLITE_CONSTRAINT_UNIQUE → DisplayNameAlreadyExists
                return enroll.error();
            }
        }

        return cert;
    }

    Result<Bytes> MeshAuthority::sign_data(BytesView data, RngRef& rng)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (!impl_->crypto_ && !impl_->authority_signer_ctx_)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "no signing capability configured");
        }

        // Sign with authority's private key (via HSM or software)
        if (impl_->authority_signer_ctx_)
        {
            return impl_->authority_signer_ctx_->sign(data, rng);
        }
        else if (impl_->crypto_->signer.sign)
        {
            return impl_->crypto_->signer.sign(data, impl_->authority_secret_key_, rng);
        }
        else
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "signer has no sign function");
        }
    }

    Result<void> MeshAuthority::verify_chain(const CertificateChain& chain) const
    {
        if (!impl_->crypto_)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "crypto not configured");
        }
        return chain.verify(*impl_->crypto_, impl_->root_public_key_);
    }

    Result<void> MeshAuthority::revoke_certificate(const std::string& cert_fingerprint, const std::string& reason)
    {
        if (!impl_->registry_)
        {
            return SMO_ERR_STORAGE(900, Error, NoRetry, None, "registry not open");
        }
        return impl_->registry_->revoke_certificate(cert_fingerprint, reason);
    }

    Result<Certificate> MeshAuthority::sign_bootstrap_csr(const BootstrapSignRequest& req)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (!impl_->crypto_ || !impl_->crypto_->signer.verify)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "crypto not configured");
        }

        // 1. Deserialize CSR
        auto csr = CertificateSigningRequest::deserialize(BytesView(req.csr_blob));
        if (!csr)
            return csr.error();

        // 2. Verify CSR signature
        auto valid = csr.value().verify(impl_->crypto_->signer, csr.value().new_public_key);
        if (!valid)
            return valid.error();
        if (!valid.value())
        {
            return SMO_ERR_CERT(209, Alert, NoRetry, None, "CSR signature invalid");
        }

        // 3. Validate slot token (simplified - in production would check against genesis slot ring)
        // For now, we just verify the slot_token is not empty
        if (req.slot_token.empty())
        {
            return SMO_ERR_CERT(220, Error, NoRetry, None, "bootstrap slot token is empty");
        }

        // 4. Validate and normalize display name
        auto name_valid = validate_display_name(csr.value().display_name);
        if (!name_valid)
            return name_valid.error();
        std::string normalized = normalize_display_name(csr.value().display_name);

        // 5. Issue certificate (subject_pubkey = ML-DSA key from CSR)
        // During bootstrap, the issuer is the Root key, not the Authority key
        if (impl_->root_public_key_.empty())
        {
            return SMO_ERR_CERT(210, Critical, NoRetry, ManualIntervention, "root public key not loaded for bootstrap signing");
        }

        Certificate cert;
        cert.subject_pubkey = csr.value().new_public_key;
        cert.issuer_pubkey = impl_->root_public_key_; // Root signs during bootstrap
        cert.mesh_id.assign(req.mesh_id.begin(), req.mesh_id.end());
        cert.display_name = normalized;
        cert.role = Role::Authority; // Bootstrap nodes become Authorities
        cert.epoch = impl_->epoch_;
        cert.not_before = now_ms() / 1000;
        cert.not_after = cert.not_before + 31536000; // +1 year

        // Sign with Root key (for bootstrap) - need root secret key
        // In production, the root secret key would be available during genesis stage
        // via RecoveryPackage unlock. Here we use authority key as fallback but mark as bootstrap.
        if (impl_->authority_secret_key_.empty() && !impl_->authority_signer_ctx_)
        {
            return SMO_ERR_CERT(210, Critical, NoRetry, ManualIntervention, "no signing key available for bootstrap");
        }

        auto body = cert.serialize();
        Bytes sig;
        if (impl_->authority_signer_ctx_)
        {
            auto sig_res = impl_->authority_signer_ctx_->sign(body, impl_->rng_);
            if (!sig_res)
                return sig_res.error();
            sig = std::move(sig_res.value());
        }
        else
        {
            auto sig_res = impl_->crypto_->signer.sign(body, impl_->authority_secret_key_, impl_->rng_);
            if (!sig_res)
                return sig_res.error();
            sig = std::move(sig_res.value());
        }
        cert.signature = std::move(sig);

        // Compute fingerprint
        auto serialized = cert.serialize();
        auto fp = impl_->crypto_->hash.hash(serialized);
        if (!fp)
            return fp.error();

        // 6. Atomic enrollment: node + cert + alias in one SQLite transaction
        if (impl_->registry_)
        {
            std::string fp_hex = smo::bytes_to_hex(fp.value());

            // Compute node_id = Blake3(public_key)
            auto node_id_result = node_id_from_public_key(csr.value().new_public_key, impl_->crypto_->hash);
            if (!node_id_result)
                return node_id_result.error();
            std::string node_id_hex = node_id_result.value().to_string();

            auto enroll = impl_->registry_->enroll_node(node_id_hex, normalized, req.mesh_id, "Authority", fp_hex,
                                                        smo::bytes_to_hex(impl_->authority_public_key_),
                                                        smo::bytes_to_hex(csr.value().new_public_key), impl_->epoch_, now_ms(),
                                                        now_ms() + 31536000000LL // +1 year
            );
            if (!enroll)
            {
                return enroll.error();
            }
        }

        return cert;
    }

    // ── Key Rotation (C7.3) ────────────────────────────────────────

    Result<std::string> MeshAuthority::initiate_key_rotation(const std::string& reason,
                                                             RngRef* rng)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (impl_->rotation_state_.rotation_pending)
        {
            return SMO_ERR_CERT(230, Error, NoRetry, None, "key rotation already in progress");
        }
        if (!impl_->crypto_ || !impl_->crypto_->signer.generate_keypair)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "no keygen function");
        }

        RngRef use_rng = rng ? *rng : impl_->rng_;

        // Generate new authority keypair
        auto new_auth_kp = impl_->crypto_->signer.generate_keypair(use_rng);
        if (!new_auth_kp)
            return new_auth_kp.error();

        // Store current key as previous
        impl_->rotation_state_.previous_authority_pubkey = impl_->authority_public_key_;
        impl_->rotation_state_.current_authority_pubkey = new_auth_kp.value().public_key;
        impl_->rotation_state_.epoch = impl_->epoch_ + 1;
        impl_->rotation_state_.rotated_at = now_ms() / 1000;
        impl_->rotation_state_.rotation_reason = reason;
        impl_->rotation_state_.rotation_pending = true;

        // Return new authority public key for out-of-band root signing
        return smo::bytes_to_hex(new_auth_kp.value().public_key);
    }

    Result<void> MeshAuthority::complete_key_rotation(const Certificate& root_signed_auth_cert,
                                                      const std::string& recovery_passphrase)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (!impl_->rotation_state_.rotation_pending)
        {
            return SMO_ERR_CERT(231, Error, NoRetry, None, "no key rotation in progress");
        }

        // Verify the new authority certificate is signed by root
        if (root_signed_auth_cert.issuer_pubkey != impl_->root_public_key_)
        {
            return SMO_ERR_CERT(232, Error, NoRetry, None, "authority certificate not signed by root");
        }
        if (root_signed_auth_cert.subject_pubkey != impl_->rotation_state_.current_authority_pubkey)
        {
            return SMO_ERR_CERT(233, Error, NoRetry, None, "authority certificate subject mismatch");
        }

        // Verify root signature
        auto valid = root_signed_auth_cert.verify(impl_->crypto_->signer);
        if (!valid || !valid.value())
        {
            return SMO_ERR_CERT(234, Error, NoRetry, None, "root signature verification failed");
        }

        // Update epoch
        impl_->epoch_ = impl_->rotation_state_.epoch;

        // Update authority keys
        impl_->authority_public_key_ = impl_->rotation_state_.current_authority_pubkey;
        impl_->authority_secret_key_.clear(); // Will be re-encrypted below

        // Re-encrypt new authority secret key
        // Note: In production with HSM, the secret key never leaves the HSM
        // This is for software mode
        if (!config_.hsm_enabled && !impl_->authority_signer_ctx_)
        {
            // Generate new secret key (in practice, this came from initiate_key_rotation)
            // We need to store it - for now we keep the old one encrypted
            // In a real implementation, the new secret key would be returned from initiate_key_rotation
            // For now, we'll re-encrypt with new passphrase
            kdf::Argon2idParams argon_params;
            BytesView aad(reinterpret_cast<const uint8_t*>(config_.mesh_id.data()), config_.mesh_id.size());

            auto enc_res = crypto::RecoveryCryptoProvider::seal(
                BytesView(impl_->authority_secret_key_.data(), impl_->authority_secret_key_.size()),
                aad,
                BytesView(reinterpret_cast<const uint8_t*>(recovery_passphrase.data()), recovery_passphrase.size()),
                argon_params,
                impl_->rng_);

            if (!enc_res)
            {
                return enc_res.error();
            }

            std::ofstream sk_file(config_.data_dir + "/authority.sec", std::ios::binary);
            sk_file.write(reinterpret_cast<const char*>(enc_res.value().data()),
                          enc_res.value().size());
        }

        // Update public key file
        std::ofstream pk_file(config_.data_dir + "/authority.pub", std::ios::binary);
        pk_file.write(reinterpret_cast<const char*>(impl_->authority_public_key_.data()),
                      impl_->authority_public_key_.size());

        // Save new authority certificate
        {
            auto auth_serialized = root_signed_auth_cert.serialize();
            std::ofstream f(config_.data_dir + "/authority.cert", std::ios::binary);
            f.write(reinterpret_cast<const char*>(auth_serialized.data()), auth_serialized.size());
        }

        // Mark rotation complete
        impl_->rotation_state_.rotation_pending = false;

        // Re-issue all active certificates under new authority key
        // This is a background operation - for now we just mark it
        // Full re-issuance would iterate all active nodes and re-sign their certs

        return {};
    }

    AuthorityKeyRotation MeshAuthority::get_rotation_state() const
    {
        return impl_->rotation_state_;
    }

    // ── Intermediate CA Management (C7.4) ────────────────────────

    Result<void> MeshAuthority::add_intermediate_ca(const IntermediateCA& ca)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        if (!impl_->crypto_ || !impl_->crypto_->signer.verify)
        {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation, "crypto not configured");
        }

        // Verify the intermediate CA certificate
        // Must be signed by root or another intermediate CA
        auto valid = ca.certificate.verify(impl_->crypto_->signer);
        if (!valid || !valid.value())
        {
            return SMO_ERR_CERT(240, Error, NoRetry, None, "intermediate CA certificate signature invalid");
        }

        // Verify issuer chain
        // For now, just check it's signed by root or an existing intermediate
        bool trusted_issuer = false;
        if (ca.certificate.issuer_pubkey == impl_->root_public_key_)
        {
            trusted_issuer = true;
        }
        else
        {
            for (const auto& existing_ca : impl_->intermediate_cas_)
            {
                if (existing_ca.certificate.subject_pubkey == ca.certificate.issuer_pubkey &&
                    existing_ca.status == "active")
                {
                    trusted_issuer = true;
                    break;
                }
            }
        }

        if (!trusted_issuer)
        {
            return SMO_ERR_CERT(241, Error, NoRetry, None, "intermediate CA issuer not trusted");
        }

        // Add to list
        impl_->intermediate_cas_.push_back(ca);

        // Persist to registry
        if (impl_->registry_)
        {
            CertificateRecord rec;
            rec.node_id_hex = ca.ca_id;
            rec.serial_number = ca.ca_id;
            rec.cert_fingerprint = smo::bytes_to_hex(ca.certificate.serialize()); // simplified
            rec.issuer_pubkey_hex = smo::bytes_to_hex(ca.certificate.issuer_pubkey);
            rec.subject_pubkey_hex = smo::bytes_to_hex(ca.certificate.subject_pubkey);
            rec.role = "IntermediateCA";
            rec.status = ca.status;
            rec.epoch = ca.epoch;
            rec.issued_at = ca.created_at;
            rec.expires_at = ca.expires_at;
            impl_->registry_->register_certificate(rec);
        }

        return {};
    }

    Result<std::vector<IntermediateCA>> MeshAuthority::list_intermediate_cas() const
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        return impl_->intermediate_cas_;
    }

    Result<std::optional<IntermediateCA>> MeshAuthority::get_intermediate_ca(const std::string& ca_id) const
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }
        for (const auto& ca : impl_->intermediate_cas_)
        {
            if (ca.ca_id == ca_id)
            {
                return std::optional<IntermediateCA>(ca);
            }
        }
        return std::optional<IntermediateCA>(std::nullopt);
    }

    Result<void> MeshAuthority::revoke_intermediate_ca(const std::string& ca_id, const std::string& reason)
    {
        if (!initialized_)
        {
            return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation, "authority not initialized");
        }

        for (auto& ca : impl_->intermediate_cas_)
        {
            if (ca.ca_id == ca_id)
            {
                ca.status = "revoked";
                // Also update in registry
                if (impl_->registry_)
                {
                    impl_->registry_->revoke_certificate(ca.ca_id, reason);
                }
                return {};
            }
        }
        return SMO_ERR_CERT(242, Error, NoRetry, None, "intermediate CA not found");
    }

    // ── Accessors ────────────────────────────────────────────────

    uint64_t MeshAuthority::current_epoch() const
    {
        return impl_->epoch_;
    }

    const Bytes& MeshAuthority::authority_public_key() const
    {
        if (!impl_)
        {
            static const Bytes kEmpty;
            return kEmpty;
        }
        return impl_->authority_public_key_;
    }

    const Bytes& MeshAuthority::root_public_key() const
    {
        if (!impl_)
        {
            static const Bytes kEmpty;
            return kEmpty;
        }
        return impl_->root_public_key_;
    }

    RngRef& MeshAuthority::rng()
    {
        if (!impl_)
        {
            static RngRef kEmpty = {nullptr, nullptr};
            return kEmpty;
        }
        return impl_->rng_;
    }

    crypto::SignerContext* MeshAuthority::authority_signer() const
    {
        if (!impl_)
            return nullptr;
        return impl_->authority_signer_ctx_.get();
    }

    const crypto::SignerMetadata& MeshAuthority::authority_key_metadata() const
    {
        static const crypto::SignerMetadata kEmpty = {};
        if (!impl_ || !impl_->authority_signer_ctx_)
            return kEmpty;
        return impl_->authority_signer_ctx_->metadata();
    }

} // namespace smo::authority