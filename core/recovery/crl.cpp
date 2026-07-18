#include "crl.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace smo::recovery {

// Big-endian helpers
namespace {
void write_u64(Bytes& out, uint64_t v) {
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

void write_u32(Bytes& out, uint32_t v) {
    for (int i = 3; i >= 0; --i)
        out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

void write_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void write_bytes(Bytes& out, const Bytes& data) {
    write_u32(out, static_cast<uint32_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
}

uint64_t read_u64(BytesView data, size_t& off) {
    uint64_t v = 0;
    for (int i = 0; i < 8 && off < data.size(); ++i)
        v = (v << 8) | data[off++];
    return v;
}

uint32_t read_u32(BytesView data, size_t& off) {
    uint32_t v = 0;
    for (int i = 0; i < 4 && off < data.size(); ++i)
        v = (v << 8) | data[off++];
    return v;
}

Bytes read_bytes(BytesView data, size_t& off) {
    uint32_t len = read_u32(data, off);
    if (off + len > data.size()) return {};
    Bytes b(data.begin() + static_cast<ptrdiff_t>(off),
            data.begin() + static_cast<ptrdiff_t>(off + len));
    off += len;
    return b;
}
} // anonymous namespace

// ===========================================================================
// CRLEntry
// ===========================================================================

Bytes CRLEntry::serialize() const {
    Bytes out;
    write_bytes(out, Bytes(cert_fingerprint.begin(), cert_fingerprint.end()));
    write_bytes(out, Bytes(node_id_hex.begin(), node_id_hex.end()));
    write_bytes(out, Bytes(reason.begin(), reason.end()));
    write_u64(out, epoch);
    write_u64(out, static_cast<uint64_t>(revoked_at));
    return out;
}

Result<CRLEntry> CRLEntry::deserialize(BytesView data) {
    CRLEntry e;
    size_t off = 0;

    auto fp_bytes = read_bytes(data, off);
    e.cert_fingerprint = std::string(fp_bytes.begin(), fp_bytes.end());

    auto nid_bytes = read_bytes(data, off);
    e.node_id_hex = std::string(nid_bytes.begin(), nid_bytes.end());

    auto reason_bytes = read_bytes(data, off);
    e.reason = std::string(reason_bytes.begin(), reason_bytes.end());

    e.epoch = read_u64(data, off);
    e.revoked_at = static_cast<int64_t>(read_u64(data, off));

    return e;
}

// ===========================================================================
// CRL
// ===========================================================================

Result<void> CRL::revoke(const std::string& cert_fingerprint,
                          const std::string& node_id_hex,
                          const std::string& reason,
                          uint64_t epoch,
                          int64_t now) {
    // Check if already revoked
    for (const auto& entry : entries_) {
        if (entry.cert_fingerprint == cert_fingerprint) {
            return Error(
                ErrorCode(ErrorCategory::Trust, 207,
                          Severity::Warn, RetryClass::NoRetry,
                          Recovery::None),
                "certificate already revoked: " + cert_fingerprint,
                __FILE__, __LINE__);
        }
    }

    CRLEntry entry;
    entry.cert_fingerprint = cert_fingerprint;
    entry.node_id_hex = node_id_hex;
    entry.reason = reason;
    entry.epoch = epoch;
    entry.revoked_at = now;

    entries_.push_back(std::move(entry));
    return {};
}

Result<bool> CRL::is_revoked(const std::string& cert_fingerprint) const {
    for (const auto& entry : entries_) {
        if (entry.cert_fingerprint == cert_fingerprint) {
            return true;
        }
    }
    return false;
}

std::vector<CRLEntry> CRL::entries_since(uint64_t epoch) const {
    std::vector<CRLEntry> result;
    for (const auto& entry : entries_) {
        if (entry.epoch >= epoch) {
            result.push_back(entry);
        }
    }
    return result;
}

Bytes CRL::serialize() const {
    Bytes out;
    write_u32(out, static_cast<uint32_t>(entries_.size()));
    for (const auto& entry : entries_) {
        Bytes ser = entry.serialize();
        write_u32(out, static_cast<uint32_t>(ser.size()));
        out.insert(out.end(), ser.begin(), ser.end());
    }
    return out;
}

Result<CRL> CRL::deserialize(BytesView data) {
    CRL crl;
    size_t off = 0;

    uint32_t n = read_u32(data, off);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t len = read_u32(data, off);
        if (off + len > data.size()) break;
        auto entry = CRLEntry::deserialize(data.subspan(off, len));
        if (!entry) break;
        crl.entries_.push_back(std::move(entry.value()));
        off += len;
    }

    return crl;
}

// ===========================================================================
// RevokeCertMsg
// ===========================================================================

Bytes RevokeCertMsg::serialize() const {
    Bytes out;
    write_bytes(out, Bytes(cert_fingerprint.begin(), cert_fingerprint.end()));
    write_bytes(out, Bytes(node_id_hex.begin(), node_id_hex.end()));
    write_bytes(out, Bytes(reason.begin(), reason.end()));
    write_u64(out, epoch);
    write_bytes(out, signature);
    return out;
}

Result<RevokeCertMsg> RevokeCertMsg::deserialize(BytesView data) {
    RevokeCertMsg msg;
    size_t off = 0;

    auto fp = read_bytes(data, off);
    msg.cert_fingerprint = std::string(fp.begin(), fp.end());

    auto nid = read_bytes(data, off);
    msg.node_id_hex = std::string(nid.begin(), nid.end());

    auto reason = read_bytes(data, off);
    msg.reason = std::string(reason.begin(), reason.end());

    msg.epoch = read_u64(data, off);
    msg.signature = read_bytes(data, off);

    return msg;
}

// ===========================================================================
// RevokeAckMsg
// ===========================================================================

Bytes RevokeAckMsg::serialize() const {
    Bytes out;
    write_bytes(out, Bytes(cert_fingerprint.begin(), cert_fingerprint.end()));
    out.push_back(accepted ? 1 : 0);
    write_bytes(out, Bytes(error_message.begin(), error_message.end()));
    return out;
}

Result<RevokeAckMsg> RevokeAckMsg::deserialize(BytesView data) {
    RevokeAckMsg msg;
    size_t off = 0;

    auto fp = read_bytes(data, off);
    msg.cert_fingerprint = std::string(fp.begin(), fp.end());

    if (off < data.size()) {
        msg.accepted = data[off++] != 0;
    }

    auto err = read_bytes(data, off);
    msg.error_message = std::string(err.begin(), err.end());

    return msg;
}

} // namespace smo::recovery

namespace smo::recovery {

// EventBus listener for RecoveryApproved events
void CRL::on_recovery_approved(const runtime::Event& ev) {
    // Parse JSON payload from event details
    // Expected: "CertificateRevocation proposal approved: {fingerprint, node_id_hex, reason, epoch}"
    std::string payload = ev.details;
    size_t brace_pos = payload.find('{');
    if (brace_pos == std::string::npos) return;

    std::string json_str = payload.substr(brace_pos);

    // Simple JSON parsing
    auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };
    auto extract_uint = [&](const std::string& json, const std::string& key) -> uint64_t {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.length();
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0;
        return std::stoull(json.substr(pos, end - pos));
    };

    std::string fingerprint = extract_field(json_str, "fingerprint");
    std::string node_id_hex = extract_field(json_str, "node_id_hex");
    std::string reason = extract_field(json_str, "reason");
    uint64_t epoch = extract_uint(json_str, "epoch");

    if (fingerprint.empty() || node_id_hex.empty()) return;

    // Get current time
    int64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    revoke(fingerprint, node_id_hex, reason, epoch, now);
}

} // namespace smo::recovery
