#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include "core/types.hpp"
#include "core/errors/error.hpp"

namespace smo {

// Execution control levels
enum class ControlLevel : uint8_t {
    Safe = 0,
    Normal = 1,
    Elevated = 2,
    Force = 3,
    Emergency = 4,
    Privileged = 5,
};

// Execution scope
enum class ExecutionScope : uint8_t {
    Single = 0,
    Mesh = 1,
    Cluster = 2,
    Global = 3,
    Quorum = 4,
    Witness = 5,
};

} // namespace smo

namespace smo::acl {

// ===========================================================================
// Policy Engine Types
// ===========================================================================

enum class PolicyDecision : uint8_t {
    Allow = 0,
    Deny = 1,
    Conditional = 2,
};

struct PolicyRule {
    std::string name;
    std::string description;
    int32_t priority = 0;
    
    // Conditions
    std::vector<std::string> required_capabilities;
    std::vector<std::string> forbidden_capabilities;
    std::vector<std::string> required_roles;
    std::vector<std::string> forbidden_roles;
    
    // Effect
    PolicyDecision effect = PolicyDecision::Allow;
    
    // Trust conditions
    std::optional<int32_t> min_trust_score;
    std::optional<int32_t> max_trust_score;
    std::vector<std::string> required_certifications;
    
    // Mesh filter
    std::string mesh_id;
    
    // Expression language
    std::string where_expression;
};

struct PolicySet {
    std::string name;
    std::string description;
    std::vector<PolicyRule> rules;
    std::string version;
    int64_t created_at = 0;
    std::string created_by;
};

struct PolicyEvaluationContext {
    std::string actor_id;
    std::string target_id;
    std::string contract_id;
    std::vector<std::string> actor_capabilities;
    std::vector<std::string> target_capabilities;
    std::vector<std::string> actor_roles;
    std::vector<std::string> target_roles;
    int32_t trust_score = 0;
    std::vector<std::string> certifications;
    std::string mesh_id;
    std::unordered_map<std::string, std::string> custom_attributes;
};

struct PolicyResult {
    PolicyDecision decision = PolicyDecision::Deny;
    std::string reason;
    std::vector<std::string> matched_rules;
    std::vector<std::string> required_capabilities;
    std::vector<std::string> missing_capabilities;
    std::vector<std::string> matched_conditions;
    std::unordered_map<std::string, std::string> metadata;
};

class PolicyEngine {
public:
    struct Config {
        std::string policy_dir;
        bool enable_caching = true;
        size_t cache_size = 10000;
        int64_t cache_ttl_ns = 5'000'000'000;  // 5 seconds
    };

    PolicyEngine();
    explicit PolicyEngine(const Config& config);
    ~PolicyEngine();

    PolicyEngine(const PolicyEngine&) = delete;
    PolicyEngine& operator=(const PolicyEngine&) = delete;
    PolicyEngine(PolicyEngine&&) = default;
    PolicyEngine& operator=(PolicyEngine&&) = default;

    // Load policies from directory or config
    Result<void> load_policies(const std::string& path);
    Result<void> load_policy_set(const PolicySet& policy_set);

    // Evaluate policy for a request
    Result<PolicyResult> evaluate(const PolicyEvaluationContext& context) const;

    // Check specific capability
    Result<bool> check_capability(const std::string& actor_id, 
                                   const std::string& capability,
                                   const std::string& target_id = "") const;

    // Get effective capabilities for actor
    Result<std::vector<std::string>> get_effective_capabilities(
        const std::string& actor_id,
        const std::string& target_id = "") const;

    // List available policies
    Result<std::vector<std::string>> list_policies() const;

    // Get policy details
    Result<PolicySet> get_policy(const std::string& name) const;

    // Reload policies
    Result<void> reload();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ===========================================================================
// Preset Policies
// ===========================================================================

namespace presets {

// Enterprise standard policy
inline const acl::PolicySet ENTERPRISE_STANDARD = {
    "enterprise-standard",
    "Standard enterprise security policy",
    {
        // Require valid certificate
        {
            "require-certificate",
            "Require valid membership certificate",
            100,
            {"CAP_VERIFY"},
            {},
            {"Member"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_VERIFY"}, {}, {}
        },
        // Allow read operations for members
        {
            "allow-read-members",
            "Allow read operations for members",
            50,
            {"CAP_FS_READ", "CAP_VERIFY"},
            {},
            {"Member", "Contributor", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            0.3f, std::nullopt, {}, {}, {}
        },
        // Allow write for contributors
        {
            "allow-write-contributors",
            "Allow write operations for contributors",
            50,
            {"CAP_FS_WRITE", "CAP_VERIFY"},
            {},
            {"Contributor", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            0.5f, std::nullopt, {}, {}, {}
        },
        // Admin operations
        {
            "admin-operations",
            "Authority can perform admin operations",
            10,
            {"CAP_ADMIN", "CAP_VERIFY"},
            {},
            {"Authority"},
            {},
            acl::PolicyDecision::Allow,
            0.8f, std::nullopt, {"CAP_ADMIN"}, {}, {}
        },
        // Deny by default
        {
            "default-deny",
            "Deny all other operations",
            -100,
            {},
            {},
            {},
            {},
            acl::PolicyDecision::Deny,
            std::nullopt, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// Read-only policy
inline const acl::PolicySet READONLY = {
    "readonly",
    "Read-only access policy",
    {
        {
            "require-certificate",
            "Require valid certificate",
            100,
            {"CAP_VERIFY"},
            {},
            {"Member"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_VERIFY"}, {}, {}
        },
        {
            "allow-read-only",
            "Allow read operations only",
            50,
            {"CAP_FS_READ", "CAP_VERIFY"},
            {},
            {"Member", "Contributor", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {}, {}, {}
        },
        {
            "deny-write",
            "Deny all write operations",
            10,
            {},
            {"CAP_FS_WRITE", "CAP_FS_DELETE", "CAP_EXEC", "CAP_ADMIN"},
            {},
            {},
            acl::PolicyDecision::Deny,
            std::nullopt, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// Backup operations policy
inline const acl::PolicySet BACKUP = {
    "backup",
    "Backup operations policy",
    {
        {
            "require-certificate",
            "Require valid certificate",
            100,
            {"CAP_VERIFY"},
            {},
            {"Member"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_VERIFY"}, {}, {}
        },
        {
            "allow-backup",
            "Allow backup operations",
            50,
            {"CAP_FS_READ", "CAP_TRANSFER", "CAP_VERIFY"},
            {},
            {"Backup", "Contributor", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {}, {}, {}
        },
        {
            "deny-other",
            "Deny non-backup operations",
            10,
            {},
            {"CAP_FS_WRITE", "CAP_EXEC", "CAP_ADMIN"},
            {},
            {},
            acl::PolicyDecision::Deny,
            std::nullopt, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// Incident response policy
inline const acl::PolicySet INCIDENT_RESPONSE = {
    "incident-response",
    "Emergency incident response policy",
    {
        {
            "require-authority",
            "Require Authority role",
            100,
            {"CAP_VERIFY"},
            {},
            {"Authority", "IncidentCommander"},
            {},
            acl::PolicyDecision::Allow,
            0.9f, std::nullopt, {"CAP_VERIFY"}, {}, {}
        },
        {
            "full-access",
            "Full access during incident",
            50,
            {"CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC", "CAP_ADMIN", "CAP_VERIFY"},
            {},
            {"Authority", "IncidentCommander"},
            {},
            acl::PolicyDecision::Allow,
            0.9f, std::nullopt, {}, {}, {}
        },
        {
            "audit-all",
            "Full audit logging",
            10,
            {"CAP_AUDIT", "CAP_VERIFY"},
            {},
            {"Authority", "IncidentCommander", "Auditor"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_AUDIT"}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// Maintenance policy
inline const acl::PolicySet MAINTENANCE = {
    "maintenance",
    "Maintenance window policy",
    {
        {
            "require-maintainer",
            "Require Maintainer role",
            100,
            {"CAP_VERIFY"},
            {},
            {"Maintainer", "Administrator", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_VERIFY"}, {}, {}
        },
        {
            "allow-maintenance",
            "Allow maintenance operations",
            50,
            {"CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC", "CAP_ADMIN", "CAP_VERIFY"},
            {},
            {"Maintainer", "Administrator", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {}, {}, {}
        },
        {
            "deny-other",
            "Deny non-maintenance operations",
            10,
            {},
            {"CAP_TRANSFER", "CAP_EXEC"},
            {},
            {},
            acl::PolicyDecision::Deny,
            std::nullopt, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// DevOps policy
inline const acl::PolicySet DEVOPS = {
    "devops",
    "DevOps automation policy",
    {
        {
            "require-devops-cert",
            "Require DevOps certificate",
            100,
            {"CAP_VERIFY", "CAP_CI_CD"},
            {},
            {"DevOps", "Administrator", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {"CAP_VERIFY", "CAP_CI_CD"}, {}, {}
        },
        {
            "allow-deploy",
            "Allow deployment operations",
            50,
            {"CAP_FS_WRITE", "CAP_EXEC", "CAP_TRANSFER", "CAP_VERIFY", "CAP_CI_CD"},
            {},
            {"DevOps", "Administrator", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            0.5f, std::nullopt, {}, {}, {}
        },
        {
            "deny-production",
            "Deny direct production changes without approval",
            10,
            {},
            {"CAP_FS_WRITE"},
            {},
            {"production"},
            acl::PolicyDecision::Deny,
            0.9f, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

// Compliance policy
inline const acl::PolicySet COMPLIANCE = {
    "compliance",
    "Regulatory compliance policy",
    {
        {
            "require-audit-cap",
            "Require audit capability",
            100,
            {"CAP_AUDIT", "CAP_VERIFY"},
            {},
            {"Auditor", "Compliance", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            0.8f, std::nullopt, {"CAP_AUDIT"}, {}, {}
        },
        {
            "audit-read",
            "Allow audit read operations",
            50,
            {"CAP_FS_READ", "CAP_AUDIT", "CAP_VERIFY"},
            {},
            {"Auditor", "Compliance", "Authority"},
            {},
            acl::PolicyDecision::Allow,
            std::nullopt, std::nullopt, {}, {}, {}
        },
        {
            "deny-modify-audit",
            "Prevent audit log modification",
            10,
            {},
            {"CAP_AUDIT_WRITE", "CAP_AUDIT_DELETE"},
            {},
            {},
            acl::PolicyDecision::Deny,
            std::nullopt, std::nullopt, {}, {}, {}
        },
    },
    "1.0",
    0,
    "system"
};

} // namespace presets

} // namespace smo::acl