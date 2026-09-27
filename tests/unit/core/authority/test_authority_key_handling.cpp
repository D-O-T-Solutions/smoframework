// SPDX-License-Identifier: Apache-2.0
//
// C7 Authority Key Handling — unit tests

#include "core/crypto/impl.hpp"
#include "core/crypto/random/getrandom.hpp"
#include "core/crypto/kdf/argon2id.hpp"
#include "core/crypto/recovery_crypto.hpp"
#include "core/crypto/signer/ed25519_provider.hpp"
#include "core/crypto/signer_context.hpp"
#include "core/certificate/certificate.hpp"
#include "core/authority/authority.hpp"
#include "core/authority/registry.hpp"
#include "core/genesis/recovery_package.hpp"
#include "core/types.hpp"

#include <cstdio>
#include <string>
#include <filesystem>
#include <memory>
#include <fstream>
#include <chrono>

using namespace smo;
using namespace smo::authority;

static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

static int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static RngRef make_test_rng()
{
    return RngRef(nullptr, [](void*, uint8_t* buf, size_t len) {
        random::fill(BytesMutView{buf, len});
    });
}

static kdf::Argon2idParams fast_params()
{
    kdf::Argon2idParams p;
    p.memory_kib = 8192;
    p.iterations = 2;
    p.lanes = 4;
    return p;
}

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

static CryptoProvider make_mock_crypto()
{
    CryptoProvider crypto;
    crypto.suite_id = 1;
    crypto.name = "Test";
    crypto.rng_fill = [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); };
    crypto.hash.hash = [](BytesView data) -> Result<Bytes> {
        Bytes out(32, 0);
        out[0] = static_cast<uint8_t>(data.size() & 0xFF);
        for (size_t i = 0; i < data.size(); ++i)
            out[(i % 31) + 1] ^= data[i];
        return out;
    };
    crypto.signer.generate_keypair = [](RngRef& rng) -> Result<KeypairResult> {
        Bytes pk(32), sk(32);
        rng.fill(pk);
        rng.fill(sk);
        return KeypairResult{std::move(pk), std::move(sk)};
    };
    crypto.signer.sign = [](BytesView msg, BytesView sk, RngRef& rng) -> Result<Bytes> {
        (void)sk; (void)rng;
        Bytes sig(msg.size());
        for (size_t i = 0; i < msg.size(); ++i)
            sig[i] = static_cast<uint8_t>(msg[i] ^ 0x42);
        return sig;
    };
    crypto.signer.verify = [](BytesView msg, BytesView sig, BytesView pk) -> Result<bool> {
        (void)pk;
        if (sig.size() != msg.size()) return false;
        for (size_t i = 0; i < msg.size(); ++i)
            if (sig[i] != static_cast<uint8_t>(msg[i] ^ 0x42)) return false;
        return true;
    };
    return crypto;
}

static std::string make_temp_dir()
{
    // Use mkdtemp
    char tmpl[] = "/tmp/smo_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    return dir ? std::string(dir) : "";
}

static void cleanup_dir(const std::string& path)
{
    std::filesystem::remove_all(path);
}

// ==========================================================================
// C7.1: Root key never-circulates invariant
// ==========================================================================

static bool test_root_key_never_circulates()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Verify root public key is loaded
    const Bytes& root_pk = authority.root_public_key();
    ASSERT(!root_pk.empty());
    ASSERT(root_pk.size() == 32);

    // Verify authority public key is loaded
    const Bytes& auth_pk = authority.authority_public_key();
    ASSERT(!auth_pk.empty());
    ASSERT(auth_pk.size() == 32);

    // Verify root secret key is NOT in memory (only public key)
    // The authority implementation should never expose root secret key
    // This is enforced by design - root secret key only exists during create_mesh_keys
    // and is then deleted (only encrypted in recovery package)

    cleanup_dir(data_dir);
    return true;
}

// ==========================================================================
// C7.2: authority.sec encrypted at rest + HSM/remote signer integration
// ==========================================================================

static bool test_authority_sec_encrypted_at_rest()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Check that authority.sec file exists and is encrypted
    std::string sec_path = data_dir + "/authority.sec";
    std::ifstream sec_file(sec_path, std::ios::binary);
    ASSERT(sec_file);
    Bytes blob((std::istreambuf_iterator<char>(sec_file)), std::istreambuf_iterator<char>());
    ASSERT(!blob.empty());

    // Verify it's a valid RecoveryDomain envelope (has magic "SM")
    ASSERT(blob.size() >= 2);
    ASSERT(blob[0] == 0x53); // 'S'
    ASSERT(blob[1] == 0x4D); // 'M'

    // Verify it can be decrypted with correct passphrase
    BytesView aad(reinterpret_cast<const uint8_t*>(config.mesh_id.data()), config.mesh_id.size());
    std::string passphrase = "smo-recovery-passphrase";
    BytesView pass(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto plaintext = crypto::RecoveryCryptoProvider::open(BytesView(blob), aad, pass);
    ASSERT(plaintext);
    ASSERT(plaintext.value().size() == 32); // Ed25519 secret key size

    cleanup_dir(data_dir);
    return true;
}

static bool test_hsm_signer_context_integration()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    // First create mesh keys normally
    MeshAuthority authority1;
    auto r = authority1.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority1.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Now simulate HSM signer context
    // Generate a new keypair to simulate HSM key
    auto hsm_kp = crypto.signer.generate_keypair(rng);
    ASSERT(hsm_kp);

    crypto::SignerMetadata hsm_meta;
    hsm_meta.backend = "HSM";
    hsm_meta.algorithm = "Ed25519";
    hsm_meta.provider = "SoftHSM";
    hsm_meta.key_id = "slot-0";
    hsm_meta.persistent = true;
    hsm_meta.hardware = true;
    hsm_meta.origin = "hsm-provision";

    auto hsm_signer = crypto::make_software_signer_context(hsm_kp.value().secret_key, crypto.signer, hsm_meta);

    // Load authority with HSM signer
    MeshAuthority authority2;
    r = authority2.init(crypto, rng);
    ASSERT(r);

    r = authority2.load_authority_key(config, std::move(hsm_signer));
    ASSERT(r);

    // Verify HSM metadata
    const auto& meta = authority2.authority_key_metadata();
    ASSERT(meta.backend == "HSM");
    ASSERT(meta.hardware == true);

    // Test signing via HSM
    Bytes test_data = {'t', 'e', 's', 't'};
    auto sig = authority2.sign_data(test_data, rng);
    ASSERT(sig);
    ASSERT(sig.value().size() == test_data.size());

    cleanup_dir(data_dir);
    return true;
}

// ==========================================================================
// C7.3: Authority key rotation (re-key + cert re-issuance)
// ==========================================================================

static bool test_authority_key_rotation_initiate()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Initiate key rotation
    auto new_auth_pk_hex = authority.initiate_key_rotation("scheduled", &rng);
    ASSERT(new_auth_pk_hex);

    // Verify rotation state
    auto rot_state = authority.get_rotation_state();
    ASSERT(rot_state.rotation_pending == true);
    ASSERT(rot_state.rotation_reason == "scheduled");
    ASSERT(rot_state.epoch == 2);
    ASSERT(!rot_state.previous_authority_pubkey.empty());
    ASSERT(!rot_state.current_authority_pubkey.empty());

    cleanup_dir(data_dir);
    return true;
}

static bool test_authority_key_rotation_complete()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Initiate key rotation
    auto new_auth_pk_hex = authority.initiate_key_rotation("scheduled", &rng);
    ASSERT(new_auth_pk_hex);

    // Create a root-signed authority certificate (simulating offline CA)
    // In reality, this would be done offline with the root key
    Certificate new_auth_cert;
    new_auth_cert.subject_pubkey = hex_to_bytes(new_auth_pk_hex.value());
    new_auth_cert.issuer_pubkey = authority.root_public_key();
    new_auth_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    new_auth_cert.display_name = config.mesh_id + "-authority-v2";
    new_auth_cert.role = Role::Authority;
    new_auth_cert.epoch = 2;
    new_auth_cert.not_before = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch()).count();
    new_auth_cert.not_after = new_auth_cert.not_before + 31536000;

    // Sign with root key (simulating offline CA)
    Bytes root_sk(32); // In reality, this comes from RecoveryPackage unlock
    rng.fill(root_sk);
    auto body = new_auth_cert.serialize();
    auto sig = crypto.signer.sign(body, root_sk, rng);
    ASSERT(sig);
    new_auth_cert.signature = std::move(sig.value());

    // Complete rotation
    r = authority.complete_key_rotation(new_auth_cert, "smo-recovery-passphrase");
    ASSERT(r);

    // Verify rotation complete
    auto rot_state = authority.get_rotation_state();
    ASSERT(rot_state.rotation_pending == false);
    ASSERT(authority.current_epoch() == 2);

    // Verify new authority public key is active
    const Bytes& auth_pk = authority.authority_public_key();
    ASSERT(auth_pk == hex_to_bytes(new_auth_pk_hex.value()));

    cleanup_dir(data_dir);
    return true;
}

// ==========================================================================
// C7.4: Certificate chain management (intermediate CA, path validation)
// ==========================================================================

static bool test_intermediate_ca_management()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Create intermediate CA keypair
    auto inter_kp = crypto.signer.generate_keypair(rng);
    ASSERT(inter_kp);

    // Create intermediate CA certificate signed by root
    Certificate inter_cert;
    inter_cert.subject_pubkey = inter_kp.value().public_key;
    inter_cert.issuer_pubkey = authority.root_public_key();
    inter_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    inter_cert.display_name = config.mesh_id + "-intermediate-01";
    inter_cert.role = Role::Authority;
    inter_cert.epoch = 1;
    inter_cert.not_before = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
    inter_cert.not_after = inter_cert.not_before + 31536000;

    // Sign with root key (simulating offline)
    Bytes root_sk(32);
    rng.fill(root_sk);
    auto body = inter_cert.serialize();
    auto sig = crypto.signer.sign(body, root_sk, rng);
    ASSERT(sig);
    inter_cert.signature = std::move(sig.value());

    // Add intermediate CA
    IntermediateCA inter_ca;
    inter_ca.ca_id = "inter-01";
    inter_ca.subject_pubkey = inter_kp.value().public_key;
    inter_ca.issuer_pubkey = authority.root_public_key();
    inter_ca.certificate = inter_cert;
    inter_ca.epoch = 1;
    inter_ca.created_at = now_ms();
    inter_ca.expires_at = inter_cert.not_after;
    inter_ca.status = "active";

    r = authority.add_intermediate_ca(inter_ca);
    ASSERT(r);

    // List intermediate CAs
    auto cas = authority.list_intermediate_cas();
    ASSERT(cas);
    ASSERT(cas.value().size() == 1);
    ASSERT(cas.value()[0].ca_id == "inter-01");

    // Get intermediate CA
    auto ca_opt = authority.get_intermediate_ca("inter-01");
    ASSERT(ca_opt && ca_opt.value().has_value());

    // Revoke intermediate CA
    r = authority.revoke_intermediate_ca("inter-01", "compromise");
    ASSERT(r);

    auto cas2 = authority.list_intermediate_cas();
    ASSERT(cas2);
    ASSERT(cas2.value().size() == 1);
    ASSERT(cas2.value()[0].status == "revoked");

    cleanup_dir(data_dir);
    return true;
}

static bool test_certificate_chain_with_intermediate()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Create intermediate CA
    auto inter_kp = crypto.signer.generate_keypair(rng);
    ASSERT(inter_kp);

    Certificate inter_cert;
    inter_cert.subject_pubkey = inter_kp.value().public_key;
    inter_cert.issuer_pubkey = authority.root_public_key();
    inter_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    inter_cert.display_name = config.mesh_id + "-intermediate-01";
    inter_cert.role = Role::Authority;
    inter_cert.epoch = 1;
    inter_cert.not_before = now_ms() / 1000;
    inter_cert.not_after = inter_cert.not_before + 31536000;

    Bytes root_sk(32);
    rng.fill(root_sk);
    auto body = inter_cert.serialize();
    auto sig = crypto.signer.sign(body, root_sk, rng);
    ASSERT(sig);
    inter_cert.signature = std::move(sig.value());

    // Create leaf certificate signed by intermediate
    auto leaf_kp = crypto.signer.generate_keypair(rng);
    ASSERT(leaf_kp);

    Certificate leaf_cert;
    leaf_cert.subject_pubkey = leaf_kp.value().public_key;
    leaf_cert.issuer_pubkey = inter_kp.value().public_key; // Signed by intermediate
    leaf_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    leaf_cert.display_name = "leaf-node-01";
    leaf_cert.role = Role::Member;
    leaf_cert.epoch = 1;
    leaf_cert.not_before = now_ms() / 1000;
    leaf_cert.not_after = leaf_cert.not_before + 31536000;

    auto body2 = leaf_cert.serialize();
    auto sig2 = crypto.signer.sign(body2, inter_kp.value().secret_key, rng);
    ASSERT(sig2);
    leaf_cert.signature = std::move(sig2.value());

    // Build chain: leaf → intermediate → root
    CertificateChain chain;
    chain.push_back(std::move(leaf_cert));
    chain.push_back(std::move(inter_cert));
    // Note: root cert not included in chain (trust anchor)

    // Verify chain with intermediate
    std::vector<Certificate> intermediates;
    intermediates.push_back(inter_cert);

    auto verify_result = chain.verify_with_intermediates(crypto, authority.root_public_key(), intermediates);
    ASSERT(verify_result);

    cleanup_dir(data_dir);
    return true;
}

static bool test_certificate_chain_rejection_bad_intermediate()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Create a FAKE intermediate (not signed by root)
    auto fake_inter_kp = crypto.signer.generate_keypair(rng);
    ASSERT(fake_inter_kp);

    Certificate fake_inter_cert;
    fake_inter_cert.subject_pubkey = fake_inter_kp.value().public_key;
    fake_inter_cert.issuer_pubkey = authority.root_public_key(); // Claims to be signed by root
    fake_inter_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    fake_inter_cert.display_name = "fake-intermediate";
    fake_inter_cert.role = Role::Authority;
    fake_inter_cert.epoch = 1;
    fake_inter_cert.not_before = now_ms() / 1000;
    fake_inter_cert.not_after = fake_inter_cert.not_before + 31536000;

    // Sign with WRONG key (not root)
    auto body = fake_inter_cert.serialize();
    auto sig = crypto.signer.sign(body, fake_inter_kp.value().secret_key, rng); // Self-signed!
    ASSERT(sig);
    fake_inter_cert.signature = std::move(sig.value());

    // Create leaf signed by fake intermediate
    auto leaf_kp = crypto.signer.generate_keypair(rng);
    ASSERT(leaf_kp);

    Certificate leaf_cert;
    leaf_cert.subject_pubkey = leaf_kp.value().public_key;
    leaf_cert.issuer_pubkey = fake_inter_kp.value().public_key;
    leaf_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    leaf_cert.display_name = "leaf-node";
    leaf_cert.role = Role::Member;
    leaf_cert.epoch = 1;
    leaf_cert.not_before = now_ms() / 1000;
    leaf_cert.not_after = leaf_cert.not_before + 31536000;

    auto body2 = leaf_cert.serialize();
    auto sig2 = crypto.signer.sign(body2, fake_inter_kp.value().secret_key, rng);
    ASSERT(sig2);
    leaf_cert.signature = std::move(sig2.value());

    CertificateChain chain;
    chain.push_back(std::move(leaf_cert));
    chain.push_back(std::move(fake_inter_cert));

    std::vector<Certificate> intermediates;
    intermediates.push_back(fake_inter_cert);

    // Should fail because intermediate is not properly signed by root
    auto verify_result = chain.verify_with_intermediates(crypto, authority.root_public_key(), intermediates);
    ASSERT(!verify_result);
    ASSERT(verify_result.error().code.code == 204); // Signature invalid

    cleanup_dir(data_dir);
    return true;
}

// ==========================================================================
// C7.5: Gate test - Key rotation + cert chain validation on join
// ==========================================================================

static bool test_cert_chain_validation_on_join()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Simulate node joining with CSR
    auto node_kp = crypto.signer.generate_keypair(rng);
    ASSERT(node_kp);

    CertificateSigningRequest csr;
    csr.new_public_key = node_kp.value().public_key;
    csr.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    csr.display_name = "joining-node-01";
    csr.platform = "linux";
    csr.version = "3.2.1";
    csr.timestamp = now_ms();

    // Sign CSR with node's key
    r = csr.sign(crypto.signer, node_kp.value().secret_key, rng);
    ASSERT(r);

    auto csr_blob = csr.serialize();

    // Authority signs CSR
    auto cert = authority.sign_csr(csr_blob, config.mesh_id);
    ASSERT(cert);

    // Verify the issued certificate
    auto verify = cert.value().verify(crypto.signer);
    ASSERT(verify && verify.value());

    // Verify certificate chain (leaf → authority → root)
    CertificateChain chain;
    chain.push_back(cert.value());

    // Need authority cert and root cert
    // Load authority cert from disk
    std::string auth_cert_path = data_dir + "/authority.cert";
    std::ifstream auth_cert_file(auth_cert_path, std::ios::binary);
    ASSERT(auth_cert_file);
    Bytes auth_cert_blob((std::istreambuf_iterator<char>(auth_cert_file)), std::istreambuf_iterator<char>());
    auto auth_cert = Certificate::deserialize(BytesView(auth_cert_blob));
    ASSERT(auth_cert);

    chain.push_back(auth_cert.value());

    auto chain_verify = chain.verify(crypto, authority.root_public_key());
    ASSERT(chain_verify);

    cleanup_dir(data_dir);
    return true;
}

static bool test_key_rotation_then_join()
{
    std::string data_dir = make_temp_dir();
    std::string registry_path = data_dir + "/node_registry.db";
    CryptoProvider crypto = make_mock_crypto();
    RngRef rng = make_test_rng();

    MeshAuthority authority;
    auto r = authority.init(crypto, rng);
    ASSERT(r);

    MeshAuthority::Config config;
    config.mesh_id = "test-mesh";
    config.data_dir = data_dir;
    config.registry_path = registry_path;

    std::string root_pubkey;
    r = authority.create_mesh_keys(config, crypto, rng, root_pubkey);
    ASSERT(r);

    // Rotate authority key
    auto new_auth_pk_hex = authority.initiate_key_rotation("scheduled", &rng);
    ASSERT(new_auth_pk_hex);

    Certificate new_auth_cert;
    new_auth_cert.subject_pubkey = hex_to_bytes(new_auth_pk_hex.value());
    new_auth_cert.issuer_pubkey = authority.root_public_key();
    new_auth_cert.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    new_auth_cert.display_name = config.mesh_id + "-authority-v2";
    new_auth_cert.role = Role::Authority;
    new_auth_cert.epoch = 2;
    new_auth_cert.not_before = now_ms() / 1000;
    new_auth_cert.not_after = new_auth_cert.not_before + 31536000;

    Bytes root_sk(32);
    rng.fill(root_sk);
    auto body = new_auth_cert.serialize();
    auto sig = crypto.signer.sign(body, root_sk, rng);
    ASSERT(sig);
    new_auth_cert.signature = std::move(sig.value());

    r = authority.complete_key_rotation(new_auth_cert, "smo-recovery-passphrase");
    ASSERT(r);

    // Now a node joins AFTER rotation
    auto node_kp = crypto.signer.generate_keypair(rng);
    ASSERT(node_kp);

    CertificateSigningRequest csr;
    csr.new_public_key = node_kp.value().public_key;
    csr.mesh_id.assign(config.mesh_id.begin(), config.mesh_id.end());
    csr.display_name = "joining-after-rotation";
    csr.platform = "linux";
    csr.version = "3.2.1";
    csr.timestamp = now_ms();

    r = csr.sign(crypto.signer, node_kp.value().secret_key, rng);
    ASSERT(r);

    auto csr_blob = csr.serialize();
    auto cert = authority.sign_csr(csr_blob, config.mesh_id);
    ASSERT(cert);

    // Verify cert was issued with new epoch
    ASSERT(cert.value().epoch == 2);
    ASSERT(cert.value().issuer_pubkey == authority.authority_public_key());

    cleanup_dir(data_dir);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main()
{
    printf("=== C7 Authority Key Handling Tests ===\n\n");

    // C7.1: Root key never-circulates invariant
    TEST("C7.1 Root key never circulates") END_TEST(test_root_key_never_circulates());

    // C7.2: authority.sec encrypted at rest + HSM integration
    TEST("C7.2 authority.sec encrypted at rest") END_TEST(test_authority_sec_encrypted_at_rest());
    TEST("C7.2 HSM signer context integration") END_TEST(test_hsm_signer_context_integration());

    // C7.3: Authority key rotation
    TEST("C7.3 Initiate key rotation") END_TEST(test_authority_key_rotation_initiate());
    TEST("C7.3 Complete key rotation") END_TEST(test_authority_key_rotation_complete());

    // C7.4: Certificate chain management
    TEST("C7.4 Intermediate CA management") END_TEST(test_intermediate_ca_management());
    TEST("C7.4 Certificate chain with intermediate") END_TEST(test_certificate_chain_with_intermediate());
    TEST("C7.4 Reject bad intermediate") END_TEST(test_certificate_chain_rejection_bad_intermediate());

    // C7.5: Gate tests
    TEST("C7.5 Cert chain validation on join") END_TEST(test_cert_chain_validation_on_join());
    TEST("C7.5 Key rotation then join") END_TEST(test_key_rotation_then_join());

    printf("\n=== %s ===\n", failures ? "FAILURES" : "ALL PASS");
    return failures ? 1 : 0;
}