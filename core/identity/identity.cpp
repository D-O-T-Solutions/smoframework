#include "identity.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace smo {

Bytes hex_to_bytes(const std::string& hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

// ---------------------------------------------------------------------------
// NodeID derivation
// ---------------------------------------------------------------------------

Result<NodeID> node_id_from_public_key(BytesView pk, const HashImpl& hash) {
    if (!hash.hash) {
        return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation,
                                "hash implementation is null");
    }
    auto digest = hash.hash(pk);
    if (!digest) return digest.error();

    NodeID id;
    size_t copy = std::min(digest.value().size(), id.value.size());
    std::memcpy(id.value.data(), digest.value().data(), copy);
    return id;
}

// ---------------------------------------------------------------------------
// IdentityState helpers
// ---------------------------------------------------------------------------

bool is_valid_transition(IdentityState from, IdentityState to) noexcept {
    switch (from) {
    case IdentityState::Uninitialized:
        return to == IdentityState::KeypairReady;
    case IdentityState::KeypairReady:
        return to == IdentityState::CertificatePending;
    case IdentityState::CertificatePending:
        return to == IdentityState::Enrolled;
    case IdentityState::Enrolled:
        return to == IdentityState::Active ||
               to == IdentityState::Suspended ||
               to == IdentityState::Retired;
    case IdentityState::Active:
        return to == IdentityState::Suspended ||
               to == IdentityState::Retired ||
               to == IdentityState::KeypairReady; // key rotation re-enters
    case IdentityState::Suspended:
        return to == IdentityState::Active ||
               to == IdentityState::Retired;
    case IdentityState::Retired:
        return false; // terminal state
    }
    return false;
}

const char* to_string(IdentityState s) noexcept {
    switch (s) {
    case IdentityState::Uninitialized:      return "Uninitialized";
    case IdentityState::KeypairReady:       return "KeypairReady";
    case IdentityState::CertificatePending: return "CertificatePending";
    case IdentityState::Enrolled:           return "Enrolled";
    case IdentityState::Active:             return "Active";
    case IdentityState::Suspended:          return "Suspended";
    case IdentityState::Retired:            return "Retired";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

Result<Identity> Identity::create(const CryptoProvider& crypto, RngRef& rng) {
    if (!crypto.signer.generate_keypair) {
        return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation,
                                "crypto provider has no keygen");
    }
    if (!crypto.hash.hash) {
        return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation,
                                "crypto provider has no hash");
    }

    auto kp = crypto.signer.generate_keypair(rng);
    if (!kp) return kp.error();

    auto pk = std::move(kp.value().public_key);
    auto sk = std::move(kp.value().secret_key);

    auto nid = node_id_from_public_key(pk, crypto.hash);
    if (!nid) return nid.error();

    return Identity(nid.value(), crypto.suite_id,
                    std::move(pk), std::move(sk),
                    IdentityState::KeypairReady);
}

Result<Identity> Identity::load(BytesView public_key, BytesView secret_key,
                                 CryptoSuiteID suite_id) {
    if (public_key.empty() || secret_key.empty()) {
        return SMO_ERR_IDENTITY(100, Error, NoRetry, RetryOperation,
                                "empty key material");
    }

    // Derive NodeID from stored public key
    // (caller must ensure the CryptoProvider is available for full hash;
    //  for now just store the public key bytes)
    NodeID id;
    size_t copy = std::min(public_key.size(), id.value.size());
    std::memcpy(id.value.data(), public_key.data(), copy);

    return Identity(id, suite_id,
                    Bytes(public_key.begin(), public_key.end()),
                    Bytes(secret_key.begin(), secret_key.end()),
                    IdentityState::KeypairReady);
}

Result<void> Identity::transition_to(IdentityState new_state) noexcept {
    if (!is_valid_transition(state_, new_state)) {
        return SMO_ERR_IDENTITY(107, Error, NoRetry, RestartFSM,
                                "invalid state transition");
    }
    state_ = new_state;
    return {};
}

std::string Identity::to_json() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"node_id\": \"" << node_id_.to_string() << "\",\n";
    json << "  \"state\": \"" << to_string(state_) << "\",\n";
    json << "  \"suite_id\": " << (int)suite_id_ << ",\n";
    json << "  \"public_key_hex\": \"" << bytes_to_hex(public_key_) << "\",\n";
    json << "  \"secret_key_hex\": \"" << bytes_to_hex(secret_key_) << "\"\n";
    json << "}\n";
    return json.str();
}

Result<void> Identity::save_to_file(const std::string& path) const {
    std::ofstream f(path);
    if (!f) {
        return SMO_ERR_STORAGE(900, Error, NoRetry, None,
                               "cannot open identity file for writing: " + path);
    }
    f << to_json();
    f.close();
    return {};
}

Result<Identity> Identity::load_from_file(const std::string& path,
                                           const CryptoProvider& crypto) {
    std::ifstream f(path);
    if (!f) {
        return SMO_ERR_STORAGE(900, Error, NoRetry, None,
                               "cannot open identity file: " + path);
    }
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();

    // Parse JSON manually (no external dependency in core)
    auto get_field = [&](const std::string& key) -> std::string {
        auto pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        auto colon = content.find(':', pos);
        if (colon == std::string::npos) return "";
        auto start = content.find('"', colon);
        if (start == std::string::npos) return "";
        auto end = content.find('"', start + 1);
        if (end == std::string::npos) return "";
        return content.substr(start + 1, end - start - 1);
    };

    auto pk_hex = get_field("public_key_hex");
    auto sk_hex = get_field("secret_key_hex");
    auto state_str = get_field("state");

    if (pk_hex.empty() || sk_hex.empty()) {
        return SMO_ERR_STORAGE(901, Error, NoRetry, None,
                               "identity file missing key material");
    }

    auto public_key = hex_to_bytes(pk_hex);
    auto secret_key = hex_to_bytes(sk_hex);

    // Derive NodeID from public key
    NodeID node_id;
    if (crypto.hash.hash) {
        auto nid = node_id_from_public_key(public_key, crypto.hash);
        if (!nid) return nid.error();
        node_id = nid.value();
    } else {
        size_t copy = std::min(public_key.size(), node_id.value.size());
        std::memcpy(node_id.value.data(), public_key.data(), copy);
    }

    IdentityState state = IdentityState::KeypairReady;
    if (state_str == "Enrolled") state = IdentityState::Enrolled;
    else if (state_str == "Active") state = IdentityState::Active;
    else if (state_str == "CertificatePending") state = IdentityState::CertificatePending;

    Identity id(node_id, crypto.suite_id,
                std::move(public_key), std::move(secret_key), state);
    return id;
}

} // namespace smo
