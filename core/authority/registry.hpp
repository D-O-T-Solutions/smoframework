#pragma once

#include "../errors/error.hpp"
#include "../types.hpp"
#include "../certificate/certificate.hpp"
#include "../identity/identity.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

struct sqlite3;

namespace smo::authority {

// ---------------------------------------------------------------------------
// AliasError — display name validation error codes
// ---------------------------------------------------------------------------
namespace AliasErrc {
    inline constexpr ErrorCode
    DisplayNameAlreadyExists(ErrorCategory::Certificate, 220, Severity::Warn,
                             RetryClass::RetrySafe, Recovery::None);
    inline constexpr ErrorCode
    InvalidDisplayName(ErrorCategory::Certificate, 221, Severity::Warn,
                       RetryClass::NoRetry, Recovery::None);
    inline constexpr ErrorCode
    DisplayNameTooLong(ErrorCategory::Certificate, 222, Severity::Warn,
                       RetryClass::NoRetry, Recovery::None);
} // namespace AliasErrc

// ---------------------------------------------------------------------------
// DisplayName validation & normalization
// ---------------------------------------------------------------------------

// Validate format: non-empty, ≤128 chars, starts with alphanumeric,
// only [a-zA-Z0-9._-]
Result<void> validate_display_name(const std::string& name) noexcept;

// Normalize: lowercase + trim (for uniqueness check)
// "SOC-HN-01" → "soc-hn-01"
std::string normalize_display_name(const std::string& name) noexcept;

// ---------------------------------------------------------------------------
// NodeRecord — a node enrolled in the mesh
// ---------------------------------------------------------------------------
struct NodeRecord {
    std::string node_id_hex;
    std::string display_name;       // normalized, UNIQUE in nodes table
    std::string mesh_id;
    std::string role;
    std::string cert_fingerprint;
    std::string status;             // "active", "suspended", "retired"
    uint64_t    epoch = 0;
    int64_t     enrolled_at = 0;
    int64_t     last_seen = 0;
};

// ---------------------------------------------------------------------------
// CertificateRecord — a certificate issued by the Authority
// ---------------------------------------------------------------------------
struct CertificateRecord {
    int64_t     id = 0;
    std::string node_id_hex;
    std::string serial_number;
    std::string cert_fingerprint;
    std::string issuer_pubkey_hex;
    std::string subject_pubkey_hex;
    std::string role;
    std::string status;             // "active", "revoked", "expired"
    uint64_t    epoch = 0;
    int64_t     issued_at = 0;
    int64_t     expires_at = 0;
    int64_t     revoked_at = 0;
    std::string revocation_reason;
};

// ---------------------------------------------------------------------------
// AliasRecord — a secondary alias for a node
// ---------------------------------------------------------------------------
struct AliasRecord {
    std::string alias;              // normalized, UNIQUE in node_aliases
    std::string node_id_hex;
    int64_t     created_at = 0;
};

// ---------------------------------------------------------------------------
// EnrollmentRecord — a pending CSR waiting for Authority action
// ---------------------------------------------------------------------------
struct EnrollmentRecord {
    int64_t     id = 0;
    std::string node_id_hex;
    std::string display_name;
    std::string mesh_id;
    std::string role;
    std::string platform;
    std::string version;
    int64_t     timestamp = 0;
    std::string csr_blob;           // serialized CSR bytes (hex)
    int64_t     submitted_at = 0;
    std::string status;             // "pending", "approved", "rejected", "expired"
};

// ---------------------------------------------------------------------------
// RevocationRecord
// ---------------------------------------------------------------------------
struct RevocationRecord {
    int64_t     id = 0;
    std::string node_id_hex;
    std::string reason;
    uint64_t    epoch = 0;
    int64_t     timestamp = 0;
};

// ---------------------------------------------------------------------------
// EnrollResult — returned after a successful atomic enrollment
// ---------------------------------------------------------------------------
struct EnrollResult {
    NodeRecord          node;
    CertificateRecord   certificate;
    std::string         cert_fingerprint;
};

// ---------------------------------------------------------------------------
// NodeRegistry — source of truth for mesh node identities
//
// This is the Authority's own database, separate from PeerStore.
// PeerStore only reflects online/discovered nodes.
// NodeRegistry is the authoritative record of ALL nodes ever enrolled.
//
// Thread safety: SQLite with FULLMUTEX + WAL mode.
// Race safety: UNIQUE constraints on display_name + alias prevent TOCTOU.
//   No SELECT-before-INSERT pattern. Always INSERT first and catch
//   SQLITE_CONSTRAINT_UNIQUE → map to DisplayNameAlreadyExists.
// ---------------------------------------------------------------------------
class NodeRegistry {
public:
    NodeRegistry() = default;
    ~NodeRegistry();

    NodeRegistry(const NodeRegistry&) = delete;
    NodeRegistry& operator=(const NodeRegistry&) = delete;

    // Open/create registry database
    Result<void> open(const std::string& db_path);
    void close();

    // ── Transaction support ───────────────────────────────────
    Result<void> begin_transaction();
    Result<void> commit();
    Result<void> rollback();

    // ── Atomic enrollment (transactional) ──────────────────────
    // Wraps node INSERT + cert INSERT + alias INSERT in one transaction.
    // Uses UNIQUE constraints for race-safe duplicate detection.
    // On SQLITE_CONSTRAINT_UNIQUE on display_name → DisplayNameAlreadyExists.
    // On SQLITE_CONSTRAINT_UNIQUE on alias → DisplayNameAlreadyExists.
    Result<EnrollResult> enroll_node(
        const std::string& node_id_hex,
        const std::string& display_name,   // will be normalized internally
        const std::string& mesh_id,
        const std::string& role,
        const std::string& cert_fingerprint,
        const std::string& cert_issuer_pubkey_hex,
        const std::string& cert_subject_pubkey_hex,
        uint64_t epoch,
        int64_t  cert_issued_at,
        int64_t  cert_expires_at
    );

    // ── Node management ───────────────────────────────────────
    Result<void> register_node(const NodeRecord& node);
    Result<std::optional<NodeRecord>> get_node(const std::string& node_id_hex) const;
    Result<std::vector<NodeRecord>> list_nodes(const std::string& mesh_id = "") const;
    Result<void> update_node_status(const std::string& node_id_hex, const std::string& status);
    Result<void> update_last_seen(const std::string& node_id_hex, int64_t timestamp);
    Result<bool> node_exists(const std::string& node_id_hex) const;

    // ── Alias management ──────────────────────────────────────
    // Aliases share namespace with display_name — no duplicate allowed.
    Result<void> register_alias(const std::string& alias, const std::string& node_id_hex);
    Result<void> release_alias(const std::string& alias);
    Result<std::optional<AliasRecord>> get_alias(const std::string& alias) const;
    Result<std::vector<AliasRecord>> list_aliases_for_node(const std::string& node_id_hex) const;

    // ── Certificate management ─────────────────────────────────
    Result<void> register_certificate(const CertificateRecord& cert);
    Result<std::optional<CertificateRecord>> get_certificate(const std::string& cert_fingerprint) const;
    Result<std::vector<CertificateRecord>> list_certificates(const std::string& node_id_hex = "") const;
    Result<void> revoke_certificate(const std::string& cert_fingerprint, const std::string& reason);
    Result<std::vector<CertificateRecord>> find_certificates_by_node(const std::string& node_id_hex) const;

    // ── Enrollment (pending CSR) ───────────────────────────────
    Result<void> submit_enrollment(const EnrollmentRecord& enrollment);
    Result<std::vector<EnrollmentRecord>> list_pending_enrollments() const;
    Result<void> update_enrollment_status(int64_t enrollment_id, const std::string& status);

    // ── Revocation list ────────────────────────────────────────
    Result<std::vector<RevocationRecord>> get_revocation_list(uint64_t since_epoch = 0) const;
    Result<void> add_revocation(const RevocationRecord& rec);

private:
    sqlite3* db_ = nullptr;
    Result<void> ensure_schema();
};

} // namespace smo::authority
