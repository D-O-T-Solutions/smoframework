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

} // namespace smo::genesis
