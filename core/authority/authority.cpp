#include "authority.hpp"

#include "../crypto/impl.hpp"
#include "../certificate/certificate.hpp"
#include "../errors/error.hpp"
#include "../identity/identity.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>

namespace smo::authority {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static Bytes hex_to_bytes(const std::string& hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

static std::string fingerprint(BytesView cert_bytes, const HashImpl& hash) {
    auto h = hash.hash(cert_bytes);
    if (!h) return "";
    return smo::bytes_to_hex(h.value());
}

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// MeshAuthority::Impl
// ---------------------------------------------------------------------------

class MeshAuthority::Impl {
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

    bool has_authority_key() const {
        return !authority_public_key_.empty() && !authority_secret_key_.empty();
    }

    // Sign a certificate using authority's private key
    Result<void> sign_certificate(Certificate& cert) {
        if (!has_authority_key()) {
            return SMO_ERR_CERT(210, Critical, NoRetry, ManualIntervention,
                                "authority key not loaded");
        }
        if (!crypto_->signer.sign) {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation,
                                  "signer has no sign function");
        }
        auto body = cert.serialize();
        auto sig = crypto_->signer.sign(body, authority_secret_key_, rng_);
        if (!sig) return sig.error();
        cert.signature = std::move(sig.value());
        return {};
    }

    // Issue a new certificate from CSR
    Result<Certificate> issue_certificate(const CertificateSigningRequest& csr,
                                           const std::string& mesh_id) {
        if (!crypto_->hash.hash) {
            return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation,
                                  "no hash function");
        }

        Certificate cert;
        cert.subject_pubkey = csr.new_public_key;
        cert.issuer_pubkey = authority_public_key_;
        cert.mesh_id = hex_to_bytes(mesh_id);
        cert.display_name = csr.display_name;
        cert.role = Role::Reader;  // Default; could be set from CSR in production
        cert.epoch = epoch_;
        cert.not_before = now_ms() / 1000;
        cert.not_after = cert.not_before + 31536000;  // +1 year

        // Sign
        auto sig_result = sign_certificate(cert);
        if (!sig_result) return sig_result.error();

        // Compute fingerprint
        auto serialized = cert.serialize();
        auto fp = crypto_->hash.hash(serialized);
        if (!fp) return fp.error();

        return cert;
    }
};

// ---------------------------------------------------------------------------
// MeshAuthority
// ---------------------------------------------------------------------------

MeshAuthority::MeshAuthority()
    : impl_(std::make_unique<Impl>()) {}

MeshAuthority::~MeshAuthority() = default;

Result<void> MeshAuthority::init(const CryptoProvider& crypto, RngRef& rng) {
    impl_->crypto_ = &crypto;
    impl_->rng_ = rng;
    initialized_ = true;
    return {};
}

Result<void> MeshAuthority::open(const Config& config) {
    config_ = config;

    // Load authority keys from disk
    std::string pk_path = config.data_dir + "/authority.pub";
    std::string sk_path = config.data_dir + "/authority.sec";

    std::ifstream pk_file(pk_path, std::ios::binary);
    std::ifstream sk_file(sk_path, std::ios::binary);
    if (!pk_file || !sk_file) {
        return SMO_ERR_IDENTITY(101, Error, NoRetry, None,
                                "authority key files not found in " + config.data_dir);
    }

    impl_->authority_public_key_ = Bytes((std::istreambuf_iterator<char>(pk_file)),
                                          std::istreambuf_iterator<char>());
    impl_->authority_secret_key_ = Bytes((std::istreambuf_iterator<char>(sk_file)),
                                          std::istreambuf_iterator<char>());

    // Open registry
    registry_ = std::make_unique<NodeRegistry>();
    auto r = registry_->open(config.registry_path);
    if (!r) return r;

    initialized_ = true;
    return {};
}

Result<void> MeshAuthority::create_mesh_keys(const Config& config,
                                              const CryptoProvider& crypto,
                                              RngRef& rng,
                                              std::string& root_pubkey_out) {
    config_ = config;
    impl_->crypto_ = &crypto;
    impl_->rng_ = rng;

    // 1. Generate Root keypair
    if (!crypto.signer.generate_keypair) {
        return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation,
                              "no keygen function");
    }
    auto root_kp = crypto.signer.generate_keypair(rng);
    if (!root_kp) return root_kp.error();

    impl_->root_public_key_ = root_kp.value().public_key;
    root_pubkey_out = smo::bytes_to_hex(impl_->root_public_key_);

    // 2. Generate Authority keypair
    auto auth_kp = crypto.signer.generate_keypair(rng);
    if (!auth_kp) return auth_kp.error();

    impl_->authority_public_key_ = auth_kp.value().public_key;
    impl_->authority_secret_key_ = auth_kp.value().secret_key;

    // 3. Create Root-signed Authority certificate
    Certificate root_cert;
    root_cert.subject_pubkey = impl_->root_public_key_;
    root_cert.issuer_pubkey = impl_->root_public_key_;  // self-signed
    root_cert.mesh_id = hex_to_bytes(config.mesh_id);
    root_cert.display_name = config.mesh_id + "-root";
    root_cert.role = Role::Root;
    root_cert.epoch = 1;
    root_cert.not_before = now_ms() / 1000;
    root_cert.not_after = root_cert.not_before + 31536000 * 10;  // 10 years

    // Sign root cert with root key
    {
        auto body = root_cert.serialize();
        auto sig = crypto.signer.sign(body, root_kp.value().secret_key, rng);
        if (!sig) return sig.error();
        root_cert.signature = std::move(sig.value());
    }

    // Authority cert signed by root
    Certificate auth_cert;
    auth_cert.subject_pubkey = impl_->authority_public_key_;
    auth_cert.issuer_pubkey = impl_->root_public_key_;
    auth_cert.mesh_id = hex_to_bytes(config.mesh_id);
    auth_cert.display_name = config.mesh_id + "-authority";
    auth_cert.role = Role::Authority;
    auth_cert.epoch = 1;
    auth_cert.not_before = now_ms() / 1000;
    auth_cert.not_after = auth_cert.not_before + 31536000;  // 1 year

    // Sign authority cert with root key
    {
        auto body = auth_cert.serialize();
        auto sig = crypto.signer.sign(body, root_kp.value().secret_key, rng);
        if (!sig) return sig.error();
        auth_cert.signature = std::move(sig.value());
    }

    // 4. Save authority keys to disk
    {
        std::ofstream pk_file(config.data_dir + "/authority.pub", std::ios::binary);
        pk_file.write(reinterpret_cast<const char*>(impl_->authority_public_key_.data()),
                      impl_->authority_public_key_.size());
        std::ofstream sk_file(config.data_dir + "/authority.sec", std::ios::binary);
        sk_file.write(reinterpret_cast<const char*>(impl_->authority_secret_key_.data()),
                      impl_->authority_secret_key_.size());
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
    if (!r) return r;

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
        auto rr = registry_->register_node(auth_node);
        if (!rr) return rr;
    }

    initialized_ = true;
    return {};
}

Result<Certificate> MeshAuthority::sign_csr(BytesView csr_blob,
                                              const std::string& mesh_id) {
    if (!initialized_) {
        return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation,
                                "authority not initialized");
    }
    if (!impl_->crypto_ || !impl_->crypto_->signer.verify) {
        return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation,
                              "crypto not configured");
    }

    // 1. Deserialize CSR
    auto csr = CertificateSigningRequest::deserialize(csr_blob);
    if (!csr) return csr.error();

    // 2. Verify CSR signature
    auto valid = csr.value().verify(impl_->crypto_->signer, csr.value().new_public_key);
    if (!valid) return valid.error();
    if (!valid.value()) {
        return SMO_ERR_CERT(209, Alert, NoRetry, None,
                            "CSR signature invalid");
    }

    // 3. Validate and normalize display name
    auto name_valid = validate_display_name(csr.value().display_name);
    if (!name_valid) return name_valid.error();
    std::string normalized = normalize_display_name(csr.value().display_name);

    // 4. Issue certificate (subject_pubkey = ML-DSA key from CSR)
    auto cert = impl_->issue_certificate(csr.value(), mesh_id);
    if (!cert) return cert.error();

    // 5. Atomic enrollment: node + cert + alias in one SQLite transaction
    if (registry_) {
        auto serialized = cert.value().serialize();
        auto fp = impl_->crypto_->hash.hash(serialized);
        if (!fp) return fp.error();
        std::string fp_hex = smo::bytes_to_hex(fp.value());

        // Compute node_id = Blake3(public_key)
        auto node_id_result = node_id_from_public_key(
            csr.value().new_public_key, impl_->crypto_->hash);
        if (!node_id_result) return node_id_result.error();
        std::string node_id_hex = node_id_result.value().to_string();

        auto enroll = registry_->enroll_node(
            node_id_hex,
            normalized,
            mesh_id,
            "Reader",
            fp_hex,
            smo::bytes_to_hex(impl_->authority_public_key_),
            smo::bytes_to_hex(csr.value().new_public_key),
            impl_->epoch_,
            now_ms(),
            now_ms() + 31536000000LL  // +1 year
        );
        if (!enroll) {
            // enroll_node() maps SQLITE_CONSTRAINT_UNIQUE → DisplayNameAlreadyExists
            return enroll.error();
        }
    }

    return cert;
}

Result<void> MeshAuthority::verify_chain(const CertificateChain& chain) const {
    if (!impl_->crypto_) {
        return SMO_ERR_CRYPTO(100, Error, NoRetry, RetryOperation,
                              "crypto not configured");
    }
    return chain.verify(*impl_->crypto_, impl_->root_public_key_);
}

Result<void> MeshAuthority::revoke_certificate(const std::string& cert_fingerprint,
                                                const std::string& reason) {
    if (!registry_) {
        return SMO_ERR_STORAGE(900, Error, NoRetry, None,
                               "registry not open");
    }
    return registry_->revoke_certificate(cert_fingerprint, reason);
}

} // namespace smo::authority
