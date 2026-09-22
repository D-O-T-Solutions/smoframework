#include "recovery_package.hpp"

#include <sstream>
#include <cstring>

namespace smo::genesis {

    static std::string json_esc(const std::string& s)
    {
        std::string out;
        out += '"';
        for (char c : s)
        {
            if (c == '"' || c == '\\')
                out += '\\';
            out += c;
        }
        out += '"';
        return out;
    }

    static std::string json_extract_str(const std::string& key, const std::string& json)
    {
        auto pos = json.find(key);
        if (pos == std::string::npos)
            return {};
        pos = json.find(':', pos);
        if (pos == std::string::npos)
            return {};
        pos = json.find_first_of('"', pos);
        if (pos == std::string::npos)
            return {};
        ++pos;
        auto end = json.find('"', pos);
        if (end == std::string::npos)
            return {};
        return json.substr(pos, end - pos);
    }

    static uint64_t json_extract_int(const std::string& key, const std::string& json)
    {
        auto pos = json.find(key);
        if (pos == std::string::npos)
            return 0;
        pos = json.find(':', pos);
        if (pos == std::string::npos)
            return 0;
        pos = json.find_first_of("0123456789", pos);
        if (pos == std::string::npos)
            return 0;
        char* end = nullptr;
        return strtoull(json.c_str() + pos, &end, 10);
    }

    Result<Bytes> RecoveryPackage::serialize() const
    {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"mesh_id\": " << json_esc(mesh_id) << ",\n";
        oss << "  \"root_public_key\": " << json_esc(root_public_key) << ",\n";
        oss << "  \"root_keypair_encrypted\": " << json_esc(bytes_to_hex(root_keypair_encrypted)) << ",\n";
        oss << "  \"crypto_domain\": \"recovery\",\n";
        oss << "  \"kdf\": \"Argon2id\",\n";
        oss << "  \"aead\": \"AES-256-GCM\",\n";
        oss << "  \"argon2_memory_kib\": " << recovery_params.memory_kib << ",\n";
        oss << "  \"argon2_iterations\": " << recovery_params.iterations << ",\n";
        oss << "  \"argon2_lanes\": " << recovery_params.lanes << ",\n";
        oss << "  \"manifest_revision\": " << manifest_revision << ",\n";
        oss << "  \"manifest_schema\": " << manifest_schema << ",\n";
        oss << "  \"genesis_manifest_json\": " << json_esc(genesis_manifest_json) << ",\n";
        oss << "  \"created_at\": " << created_at << "\n";
        oss << "}\n";

        std::string str = oss.str();
        return Bytes(str.begin(), str.end());
    }

    Result<RecoveryPackage> RecoveryPackage::deserialize(BytesView data)
    {
        std::string json(reinterpret_cast<const char*>(data.data()), data.size());

        RecoveryPackage pkg;
        pkg.mesh_id = json_extract_str("mesh_id", json);
        pkg.root_public_key = json_extract_str("root_public_key", json);
        pkg.genesis_manifest_json = json_extract_str("genesis_manifest_json", json);
        pkg.manifest_revision = (uint32_t)json_extract_int("manifest_revision", json);
        pkg.manifest_schema = (uint32_t)json_extract_int("manifest_schema", json);
        pkg.created_at = json_extract_int("created_at", json);

        // Recovery domain params (optional in JSON — defaults match SPEC §7.8).
        pkg.recovery_params.memory_kib = (uint32_t)json_extract_int("argon2_memory_kib", json);
        pkg.recovery_params.iterations = (uint32_t)json_extract_int("argon2_iterations", json);
        pkg.recovery_params.lanes = (uint32_t)json_extract_int("argon2_lanes", json);
        if (pkg.recovery_params.memory_kib == 0)
            pkg.recovery_params.memory_kib = smo::kdf::Argon2idParams{}.memory_kib;
        if (pkg.recovery_params.iterations == 0)
            pkg.recovery_params.iterations = smo::kdf::Argon2idParams{}.iterations;
        if (pkg.recovery_params.lanes == 0)
            pkg.recovery_params.lanes = smo::kdf::Argon2idParams{}.lanes;

        // Decode hex keypair envelope
        auto hex_str = json_extract_str("root_keypair_encrypted", json);
        if (!hex_str.empty())
        {
            pkg.root_keypair_encrypted.resize(hex_str.size() / 2);
            for (size_t i = 0; i < hex_str.size(); i += 2)
            {
                auto byte_str = hex_str.substr(i, 2);
                pkg.root_keypair_encrypted[i / 2] = (uint8_t)strtoul(byte_str.c_str(), nullptr, 16);
            }
        }

        if (pkg.mesh_id.empty() || pkg.root_public_key.empty())
        {
            return SMO_ERR_GENESIS(1404, Critical, NoRetry, ManualIntervention,
                                   "recovery package missing required fields");
        }

        return pkg;
    }

    bool RecoveryPackage::verify_passphrase(const std::string& passphrase) const
    {
        if (root_keypair_encrypted.empty())
            return false;

        BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
        auto plain_res = smo::crypto::RecoveryCryptoProvider::open(
            BytesView(root_keypair_encrypted), aad,
            BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
        return static_cast<bool>(plain_res);
    }

    Result<RootSession> RecoveryPackage::unlock(const std::string& passphrase, const SignerImpl& signer,
                                                RngRef& rng) const
    {
        if (!verify_passphrase(passphrase))
        {
            return SMO_ERR_GENESIS(1404, Error, NoRetry, ManualIntervention, "incorrect recovery passphrase");
        }

        // Version compatibility check
        if (manifest_schema < 1 || manifest_schema > 1)
        {
            return SMO_ERR_GENESIS(1408, Error, NoRetry, ManualIntervention,
                                   "recovery package schema " + std::to_string(manifest_schema) +
                                       " is not supported (expected 1)");
        }

        if (root_keypair_encrypted.empty())
        {
            return SMO_ERR_GENESIS(1404, Critical, NoRetry, ManualIntervention,
                                   "recovery package has no encrypted keypair");
        }

        // ── 1. Open the RecoveryDomain envelope (Argon2id + AES-256-GCM) ───
        BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
        auto plaintext_res = smo::crypto::RecoveryCryptoProvider::open(
            BytesView(root_keypair_encrypted), aad,
            BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
        if (!plaintext_res)
        {
            return SMO_ERR_GENESIS(1404, Error, NoRetry, ManualIntervention,
                                   "failed to decrypt recovery keypair: " + plaintext_res.error().message);
        }
        auto plaintext = std::move(plaintext_res).value();

        // ── 2. Parse plaintext: 2-byte BE pubkey_len || pubkey || secret_key ──
        BytesView seckey_raw;
        if (plaintext.size() >= 3)
        {
            uint16_t pubkey_len = (static_cast<uint16_t>(plaintext[0]) << 8) | static_cast<uint16_t>(plaintext[1]);
            size_t expected = static_cast<size_t>(pubkey_len) + 2;
            if (pubkey_len > 0 && plaintext.size() > expected)
            {
                BytesView pubkey_raw(plaintext.data() + 2, pubkey_len);
                seckey_raw = BytesView(plaintext.data() + 2 + pubkey_len, plaintext.size() - 2 - pubkey_len);
                // Best-effort consistency check
                auto pubkey_hex = bytes_to_hex(pubkey_raw);
                (void)pubkey_hex;
            }
        }
        if (seckey_raw.empty())
        {
            // Compatibility fallback: entire plaintext is the secret key
            seckey_raw = BytesView(plaintext);
        }

        // ── 3. Build SignerContext + RootSession ───────────────────────
        smo::crypto::SignerMetadata meta;
        meta.backend = "Software";
        meta.algorithm = "Unknown (recovery)";
        meta.persistent = false;
        meta.hardware = false;
        meta.origin = "recovery-package";
        meta.created_at = created_at;

        auto sc = smo::crypto::make_software_signer_context(seckey_raw, signer, std::move(meta));

        // Default full-policy session; caller may adjust.
        RootSession session;
        session.root_node_id = "root";
        session.root_public_key = root_public_key;
        session.signer = std::move(sc);
        // policy and audit_sink left as defaults (full access, no-op sink)

        return session;
    }

    Result<UnlockedKeypair> RecoveryPackage::unlock_keypair(const std::string& passphrase) const
    {
        if (!verify_passphrase(passphrase))
        {
            return SMO_ERR_GENESIS(1404, Error, NoRetry, ManualIntervention, "incorrect recovery passphrase");
        }

        if (manifest_schema < 1 || manifest_schema > 1)
        {
            return SMO_ERR_GENESIS(1408, Error, NoRetry, ManualIntervention,
                                   "recovery package schema " + std::to_string(manifest_schema) +
                                       " is not supported (expected 1)");
        }

        if (root_keypair_encrypted.empty())
        {
            return SMO_ERR_GENESIS(1404, Critical, NoRetry, ManualIntervention,
                                   "recovery package has no encrypted keypair");
        }

        BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
        auto plaintext_res = smo::crypto::RecoveryCryptoProvider::open(
            BytesView(root_keypair_encrypted), aad,
            BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
        if (!plaintext_res)
        {
            return SMO_ERR_GENESIS(1404, Error, NoRetry, ManualIntervention,
                                   "failed to decrypt recovery keypair: " + plaintext_res.error().message);
        }
        auto plaintext = std::move(plaintext_res).value();

        UnlockedKeypair kp;
        if (plaintext.size() >= 3)
        {
            uint16_t pubkey_len = (static_cast<uint16_t>(plaintext[0]) << 8) | static_cast<uint16_t>(plaintext[1]);
            size_t expected = static_cast<size_t>(pubkey_len) + 2;
            if (pubkey_len > 0 && plaintext.size() > expected)
            {
                kp.public_key.assign(plaintext.begin() + 2, plaintext.begin() + 2 + pubkey_len);
                kp.secret_key.assign(plaintext.begin() + 2 + pubkey_len, plaintext.end());
            }
        }
        if (kp.secret_key.empty())
        {
            kp.secret_key = plaintext;
        }
        return kp;
    }

// ==========================================================================
// ShamirSharePackage implementation
// ==========================================================================

Result<Bytes> ShamirSharePackage::serialize() const
{
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"shareholder_index\": " << static_cast<int>(shareholder_index) << ",\n";
    oss << "  \"encrypted_share\": " << json_esc(bytes_to_hex(encrypted_share)) << ",\n";
    oss << "  \"kdf\": \"Argon2id\",\n";
    oss << "  \"argon2_memory_kib\": " << kdf_params.memory_kib << ",\n";
    oss << "  \"argon2_iterations\": " << kdf_params.iterations << ",\n";
    oss << "  \"argon2_lanes\": " << kdf_params.lanes << "\n";
    oss << "}\n";

    std::string str = oss.str();
    return Bytes(str.begin(), str.end());
}

Result<ShamirSharePackage> ShamirSharePackage::deserialize(BytesView data)
{
    std::string json(reinterpret_cast<const char*>(data.data()), data.size());

    ShamirSharePackage pkg;
    pkg.shareholder_index = static_cast<uint8_t>(json_extract_int("shareholder_index", json));

    // Decode hex encrypted_share
    auto hex_str = json_extract_str("encrypted_share", json);
    if (!hex_str.empty())
    {
        pkg.encrypted_share.resize(hex_str.size() / 2);
        for (size_t i = 0; i < hex_str.size(); i += 2)
        {
            auto byte_str = hex_str.substr(i, 2);
            pkg.encrypted_share[i / 2] = static_cast<uint8_t>(strtoul(byte_str.c_str(), nullptr, 16));
        }
    }

    // KDF params
    pkg.kdf_params.memory_kib = static_cast<uint32_t>(json_extract_int("argon2_memory_kib", json));
    pkg.kdf_params.iterations = static_cast<uint32_t>(json_extract_int("argon2_iterations", json));
    pkg.kdf_params.lanes = static_cast<uint32_t>(json_extract_int("argon2_lanes", json));
    if (pkg.kdf_params.memory_kib == 0)
        pkg.kdf_params.memory_kib = smo::kdf::Argon2idParams{}.memory_kib;
    if (pkg.kdf_params.iterations == 0)
        pkg.kdf_params.iterations = smo::kdf::Argon2idParams{}.iterations;
    if (pkg.kdf_params.lanes == 0)
        pkg.kdf_params.lanes = smo::kdf::Argon2idParams{}.lanes;

    if (pkg.shareholder_index == 0)
    {
        return SMO_ERR_GENESIS(1410, Error, NoRetry, ManualIntervention, "ShamirSharePackage: shareholder_index cannot be 0");
    }

    return pkg;
}

Result<crypto::ShamirShare> ShamirSharePackage::unlock_share(const std::string& passphrase) const
{
    BytesView aad(reinterpret_cast<const uint8_t*>("shamir-share"), 12);
    auto plain_res = smo::crypto::RecoveryCryptoProvider::open(
        BytesView(encrypted_share), aad,
        BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()));
    if (!plain_res)
    {
        return SMO_ERR_GENESIS(1411, Error, NoRetry, ManualIntervention,
                               "failed to decrypt share: " + plain_res.error().message);
    }
    auto plaintext = std::move(plain_res).value();

    // Plaintext should be a serialized ShamirShare (33 bytes)
    if (plaintext.size() != 33)
    {
        return SMO_ERR_GENESIS(1412, Error, NoRetry, ManualIntervention,
                               "decrypted share has invalid size (expected 33)");
    }

    return crypto::ShamirShare::deserialize(BytesView(plaintext));
}

// ==========================================================================
// RecoveryPackageV2 implementation
// ==========================================================================

Result<Bytes> RecoveryPackageV2::serialize() const
{
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": " << static_cast<int>(kVersion) << ",\n";
    oss << "  \"mesh_id\": " << json_esc(mesh_id) << ",\n";
    oss << "  \"root_public_key\": " << json_esc(root_public_key) << ",\n";
    oss << "  \"manifest_revision\": " << manifest_revision << ",\n";
    oss << "  \"manifest_schema\": " << manifest_schema << ",\n";
    oss << "  \"genesis_manifest_json\": " << json_esc(genesis_manifest_json) << ",\n";
    oss << "  \"created_at\": " << created_at << ",\n";
    oss << "  \"threshold\": " << static_cast<int>(threshold) << ",\n";
    oss << "  \"total_shares\": " << static_cast<int>(total_shares) << ",\n";
    oss << "  \"default_kdf\": \"Argon2id\",\n";
    oss << "  \"default_argon2_memory_kib\": " << default_kdf_params.memory_kib << ",\n";
    oss << "  \"default_argon2_iterations\": " << default_kdf_params.iterations << ",\n";
    oss << "  \"default_argon2_lanes\": " << default_kdf_params.lanes << ",\n";
    oss << "  \"shares\": [\n";

    for (size_t i = 0; i < shares.size(); ++i)
    {
        auto share_ser = shares[i].serialize();
        if (!share_ser)
            return share_ser.error();
        std::string share_json(reinterpret_cast<const char*>(share_ser.value().data()), share_ser.value().size());
        // Remove trailing newline and indent
        if (!share_json.empty() && share_json.back() == '\n')
            share_json.pop_back();
        oss << "    " << share_json;
        if (i + 1 < shares.size())
            oss << ",";
        oss << "\n";
    }
    oss << "  ]\n";
    oss << "}\n";

    std::string str = oss.str();
    return Bytes(str.begin(), str.end());
}

Result<RecoveryPackageV2> RecoveryPackageV2::deserialize(BytesView data)
{
    std::string json(reinterpret_cast<const char*>(data.data()), data.size());

    RecoveryPackageV2 pkg;
    pkg.mesh_id = json_extract_str("mesh_id", json);
    pkg.root_public_key = json_extract_str("root_public_key", json);
    pkg.genesis_manifest_json = json_extract_str("genesis_manifest_json", json);
    pkg.manifest_revision = static_cast<uint32_t>(json_extract_int("manifest_revision", json));
    pkg.manifest_schema = static_cast<uint32_t>(json_extract_int("manifest_schema", json));
    pkg.created_at = json_extract_int("created_at", json);
    pkg.threshold = static_cast<uint8_t>(json_extract_int("threshold", json));
    pkg.total_shares = static_cast<uint8_t>(json_extract_int("total_shares", json));

    // Default KDF params
    pkg.default_kdf_params.memory_kib = static_cast<uint32_t>(json_extract_int("default_argon2_memory_kib", json));
    pkg.default_kdf_params.iterations = static_cast<uint32_t>(json_extract_int("default_argon2_iterations", json));
    pkg.default_kdf_params.lanes = static_cast<uint32_t>(json_extract_int("default_argon2_lanes", json));
    if (pkg.default_kdf_params.memory_kib == 0)
        pkg.default_kdf_params.memory_kib = smo::kdf::Argon2idParams{}.memory_kib;
    if (pkg.default_kdf_params.iterations == 0)
        pkg.default_kdf_params.iterations = smo::kdf::Argon2idParams{}.iterations;
    if (pkg.default_kdf_params.lanes == 0)
        pkg.default_kdf_params.lanes = smo::kdf::Argon2idParams{}.lanes;

    // Parse shares array - simple JSON array parsing
    size_t shares_start = json.find("\"shares\":");
    if (shares_start != std::string::npos)
    {
        shares_start = json.find('[', shares_start);
        if (shares_start != std::string::npos)
        {
            size_t shares_end = json.find(']', shares_start);
            if (shares_end != std::string::npos)
            {
                std::string shares_json = json.substr(shares_start + 1, shares_end - shares_start - 1);
                // Simple parsing: find each { ... } object
                size_t pos = 0;
                while (pos < shares_json.size())
                {
                    size_t obj_start = shares_json.find('{', pos);
                    if (obj_start == std::string::npos)
                        break;
                    size_t obj_end = shares_json.find('}', obj_start);
                    if (obj_end == std::string::npos)
                        break;

                    std::string share_obj = shares_json.substr(obj_start, obj_end - obj_start + 1);
                    Bytes share_bytes(share_obj.begin(), share_obj.end());
                    auto share_res = ShamirSharePackage::deserialize(BytesView(share_bytes));
                    if (!share_res)
                        return share_res.error();
                    pkg.shares.push_back(std::move(share_res).value());

                    pos = obj_end + 1;
                }
            }
        }
    }

    if (pkg.mesh_id.empty() || pkg.root_public_key.empty())
    {
        return SMO_ERR_GENESIS(1413, Critical, NoRetry, ManualIntervention,
                               "recovery package v2 missing required fields");
    }
    if (pkg.threshold == 0 || pkg.threshold > pkg.total_shares)
    {
        return SMO_ERR_GENESIS(1414, Critical, NoRetry, ManualIntervention,
                               "recovery package v2 invalid threshold/total_shares");
    }
    if (pkg.shares.size() != pkg.total_shares)
    {
        return SMO_ERR_GENESIS(1415, Critical, NoRetry, ManualIntervention,
                               "recovery package v2 share count mismatch");
    }

    return pkg;
}

Result<crypto::ShamirShare> RecoveryPackageV2::verify_and_unlock_share(uint8_t shareholder_index, const std::string& passphrase) const
{
    for (const auto& share_pkg : shares)
    {
        if (share_pkg.shareholder_index == shareholder_index)
        {
            return share_pkg.unlock_share(passphrase);
        }
    }
    return SMO_ERR_GENESIS(1416, Error, NoRetry, ManualIntervention,
                           "shareholder index " + std::to_string(shareholder_index) + " not found");
}

Result<UnlockedKeypair> RecoveryPackageV2::recover(const std::vector<std::pair<uint8_t, std::string>>& passphrases) const
{
    if (passphrases.size() < threshold)
    {
        return SMO_ERR_GENESIS(1417, Error, NoRetry, ManualIntervention,
                               "insufficient passphrases provided (need at least " + std::to_string(threshold) + ")");
    }

    std::vector<crypto::ShamirShare> recovered_shares;
    recovered_shares.reserve(passphrases.size());

    for (const auto& [idx, pass] : passphrases)
    {
        auto share_res = verify_and_unlock_share(idx, pass);
        if (!share_res)
            return share_res.error();
        recovered_shares.push_back(std::move(share_res).value());
    }

    // Use Shamir recover with threshold M
    auto secret_res = smo::crypto::shamir_recover(recovered_shares, threshold);
    if (!secret_res)
        return secret_res.error();

    auto secret = std::move(secret_res).value();
    if (secret.size() != 32)
    {
        return SMO_ERR_GENESIS(1418, Error, NoRetry, ManualIntervention,
                               "recovered secret has invalid size (expected 32)");
    }

    // Derive keypair from secret (Ed25519 seed expansion)
    // The secret is the Ed25519 seed (32 bytes)
    auto kp_res = smo::signer::Ed25519Provider::derive_keypair_from_seed(BytesView(secret));
    if (!kp_res)
        return kp_res.error();

    UnlockedKeypair kp;
    kp.public_key = std::move(kp_res.value().public_key);
    kp.secret_key = std::move(kp_res.value().secret_key);

    // Verify public key matches
    if (bytes_to_hex(kp.public_key) != root_public_key)
    {
        return SMO_ERR_GENESIS(1419, Error, NoRetry, ManualIntervention,
                               "recovered public key does not match package root_public_key");
    }

    return kp;
}

Result<RecoveryPackageV2> RecoveryPackageV2::create(const std::string& mesh_id,
                                                     const UnlockedKeypair& keypair,
                                                     uint8_t threshold, uint8_t total_shares,
                                                     const smo::kdf::Argon2idParams& default_kdf_params,
                                                     const std::vector<std::string>& shareholder_passphrases,
                                                     RngRef& rng)
{
    if (threshold == 0 || threshold > total_shares)
    {
        return SMO_ERR_GENESIS(1420, Error, NoRetry, ManualIntervention, "invalid threshold/total_shares");
    }
    if (shareholder_passphrases.size() != total_shares)
    {
        return SMO_ERR_GENESIS(1421, Error, NoRetry, ManualIntervention,
                               "shareholder_passphrases count must equal total_shares");
    }
    if (total_shares > 255)
    {
        return SMO_ERR_GENESIS(1422, Error, NoRetry, ManualIntervention, "total_shares cannot exceed 255");
    }

    // Prepare 32-byte secret (Ed25519 seed from secret key)
    Bytes secret;
    if (keypair.secret_key.size() == 32)
    {
        secret = keypair.secret_key;
    }
    else if (keypair.secret_key.size() == 64)
    {
        // Ed25519 secret key is 64 bytes (seed + public key), first 32 is seed
        secret.assign(keypair.secret_key.begin(), keypair.secret_key.begin() + 32);
    }
    else
    {
        return SMO_ERR_GENESIS(1423, Error, NoRetry, ManualIntervention, "invalid secret key size");
    }

    // Split secret into Shamir shares
    auto shares_res = smo::crypto::shamir_split(BytesView(secret), total_shares, threshold, rng);
    if (!shares_res)
        return shares_res.error();
    auto shamir_shares = std::move(shares_res).value();

    // Encrypt each share with its shareholder's passphrase
    std::vector<ShamirSharePackage> share_packages;
    share_packages.reserve(total_shares);

    for (uint8_t i = 0; i < total_shares; ++i)
    {
        const auto& share = shamir_shares[i];
        const auto& passphrase = shareholder_passphrases[i];

        // Serialize share
        auto share_ser = share.serialize();
        if (!share_ser)
            return share_ser.error();

        // Encrypt with shareholder's passphrase (using mesh_id as AAD for share)
        BytesView aad(reinterpret_cast<const uint8_t*>("shamir-share"), 12);
        BytesView pass(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

        auto envelope_res = smo::crypto::RecoveryCryptoProvider::seal(
            BytesView(share_ser.value()), aad, pass, default_kdf_params, rng);
        if (!envelope_res)
            return envelope_res.error();

        ShamirSharePackage sp;
        sp.shareholder_index = share.index;
        sp.encrypted_share = std::move(envelope_res).value();
        sp.kdf_params = default_kdf_params;
        share_packages.push_back(std::move(sp));
    }

    RecoveryPackageV2 pkg;
    pkg.mesh_id = mesh_id;
    pkg.root_public_key = bytes_to_hex(keypair.public_key);
    pkg.threshold = threshold;
    pkg.total_shares = total_shares;
    pkg.shares = std::move(share_packages);
    pkg.default_kdf_params = default_kdf_params;
    pkg.created_at = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    return pkg;
}

} // namespace smo::genesis
