# RFC 0029 — Policy Engine

**Status:** ACCEPTED  
**Date:** 2026-07-16  
**Authors:** dotlinux26, D-O-T-Solutions

---

## Summary

This RFC defines the **Policy Engine** — the authorization subsystem that evaluates whether a contract execution is permitted based on capabilities, roles, trust scores, and custom expressions.

---

## Motivation

SMO operates in untrusted environments where nodes must make autonomous decisions about contract execution. The Policy Engine provides:

1. **Capability-based authorization** (not role-based)
2. **Declarative policies** (YAML/JSON)
3. **Conflict resolution** (priority-based)
4. **Audit trail** for every decision

---

## Architecture

```
Request
    ↓
Policy Evaluation Context
    ↓
Policy Engine (Priority-ordered rules)
    ↓
Allow / Deny / Conditional
```

---

## Core Concepts

### Capabilities

Capabilities are fine-grained permissions, not roles:

```
CAP_FS_READ
CAP_FS_WRITE
CAP_FS_DELETE
CAP_EXEC_BASIC
CAP_EXEC_ADVANCED
CAP_TRANSFER
CAP_ADMIN
CAP_AUDIT
CAP_VERIFY
CAP_QUARANTINE
CAP_SIGN_NODE
CAP_GRANT
CAP_REVOKE
CAP_QUARANTINE
CAP_EPOCH_INCREMENT
CAP_POLICY_CHANGE
CAP_NODE_BOOTSTRAP
```

### Roles (Presets)

Roles are **capability presets** — convenience groupings:

| Role | Capabilities |
|------|-------------|
| `Observer` | `CAP_VERIFY`, `CAP_AUDIT` |
| `Member` | `Observer` + `CAP_FS_READ`, `CAP_SESSION_CREATE` |
| `Contributor` | `Member` + `CAP_FS_WRITE`, `CAP_EXEC_BASIC` |
| `Administrator` | `Contributor` + `CAP_GRANT`, `CAP_REVOKE`, `CAP_QUARANTINE`, `CAP_SIGN_NODE`, `CAP_EPOCH_INCREMENT`, `CAP_POLICY_CHANGE`, `CAP_NODE_BOOTSTRAP` |

**Key principle:** Runtime only checks **capabilities**, never roles. Roles are configuration-time only.

---

## Policy Rules

### Rule Structure

```yaml
- name: "require-certificate"
  description: "Require valid certificate for mesh access"
  priority: 100
  requires:
    capabilities:
      - CAP_VERIFY
  effect: allow

- name: "deny-write-for-readonly"
  description: "Prevent write operations for read-only roles"
  priority: 50
  forbids:
    capabilities:
      - CAP_FS_WRITE
      - CAP_FS_DELETE
      - CAP_EXEC_BASIC
  effect: deny
```

### Condition Expressions

```yaml
- name: "high-trust-deploy"
  description: "Allow deploy only for high-trust nodes"
  priority: 75
  where: 'trust > 0.8 && role == "Deployer"'
  effect: allow
```

Supported operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `&&`, `||`, `!`, `in`, `contains`, `matches`

---

## Policy Engine API

### Execution Control Enums (`core/acl/policy_engine.hpp`)

```cpp
namespace smo {

enum class ControlLevel : uint8_t {
    Safe = 0,       // Read-only, no side effects
    Normal = 1,     // Standard operations
    Elevated = 2,   // Requires elevated privileges
    Force = 3,      // Force execution (override warnings)
    Emergency = 4,  // Emergency override (audit required)
    Privileged = 5, // System-level operations
};

enum class ExecutionScope : uint8_t {
    Single = 0,   // Execute on one node
    Mesh = 1,     // Execute on all mesh nodes
    Cluster = 2,  // Execute on cluster subset
    Global = 3,   // Execute across all reachable nodes
    Quorum = 4,   // Execute on quorum (majority)
    Witness = 5,  // Execute on witness nodes only
};

} // namespace smo
```

### PolicyRule Struct

```cpp
namespace smo::acl {

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
```

### PolicyEngine Class

```cpp
class PolicyEngine {
    struct Config {
        std::string policy_dir;
        bool enable_caching = true;
        size_t cache_size = 10000;
        int64_t cache_ttl_ns = 5'000'000'000;  // 5 seconds
    };

    PolicyEngine();
    explicit PolicyEngine(const Config& config);

    Result<void> load_policies(const std::string& path);
    Result<void> load_policy_set(const PolicySet& policy_set);
    Result<PolicyResult> evaluate(const PolicyEvaluationContext& context) const;
    Result<bool> check_capability(const std::string& actor_id,
                                   const std::string& capability,
                                   const std::string& target_id = "") const;
    Result<std::vector<std::string>> get_effective_capabilities(
        const std::string& actor_id,
        const std::string& target_id = "") const;
    Result<std::vector<std::string>> list_policies() const;
    Result<PolicySet> get_policy(const std::string& name) const;
    Result<void> reload();
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

struct PolicyResult {   // Renamed from PolicyDecision (name collision fix)
    PolicyDecision decision = PolicyDecision::Deny;
    std::string reason;
    std::vector<std::string> matched_rules;
    std::vector<std::string> required_capabilities;
    std::vector<std::string> missing_capabilities;
    std::vector<std::string> matched_conditions;
    std::unordered_map<std::string, std::string> metadata;
};
```

### Design Note: `PolicyDecision` vs `PolicyResult`

The enum `PolicyDecision` (Allow/Deny/Conditional) is separate from the struct `PolicyResult`. The original design had a struct named `PolicyDecision` which caused a name collision with the enum. Fixed by renaming the struct to `PolicyResult`.

---

## Preset Policies (defined in `core/acl/policy_engine.hpp`)

| Preset | File Variable | Rules | Use Case |
|--------|--------------|-------|----------|
| `enterprise-standard` | `presets::ENTERPRISE_STANDARD` | require-certificate(100), allow-read-members(50), allow-write-contributors(50), admin-operations(10), default-deny(-100) | General enterprise mesh |
| `readonly` | `presets::READONLY` | require-certificate(100), allow-read-only(50), deny-write(10) | Read-only access |
| `backup` | `presets::BACKUP` | require-certificate(100), allow-backup(50), deny-other(10) | Backup operators |
| `incident-response` | `presets::INCIDENT_RESPONSE` | require-authority(100), full-access(50), audit-all(10) | Emergency access |
| `maintenance` | `presets::MAINTENANCE` | require-maintainer(100), allow-maintenance(50), deny-other(10) | Maintenance windows |
| `devops` | `presets::DEVOPS` | require-devops-cert(100), allow-deploy(50), deny-production(10) | CI/CD pipelines |
| `compliance` | `presets::COMPLIANCE` | require-audit-cap(100), audit-read(50), deny-modify-audit(10) | Audit/regulatory |

---

## Conflict Resolution

1. **Highest priority wins** (higher number = higher priority)
2. **Explicit deny beats allow** at same priority
3. **Explicit allow beats implicit deny**
4. **Explicit rules beat inherited defaults**

---

## Capability Inheritance

```yaml
# Capability hierarchy (implied grants)
CAP_ADMIN:
  - CAP_GRANT
  - CAP_REVOKE
  - CAP_QUARANTINE
  - CAP_SIGN_NODE
  - CAP_EPOCH_INCREMENT
  - CAP_POLICY_CHANGE
  - CAP_NODE_BOOTSTRAP
  - (inherits CONTRIBUTOR)

CAP_CONTRIBUTOR:
  - CAP_FS_WRITE
  - CAP_EXEC_BASIC
  - (inherits MEMBER)

CAP_MEMBER:
  - CAP_FS_READ
  - CAP_VERIFY
  - CAP_SESSION_CREATE
  - (inherits OBSERVER)

CAP_OBSERVER:
  - CAP_VERIFY
  - CAP_AUDIT
  - CAP_SESSION_CREATE
```

---

## Implementation Notes

- **Caching**: Cache decisions for 5 seconds (configurable via `cache_ttl_ns`)
- **Cache invalidation**: On policy change, capability change, trust change
- **Performance target**: <1ms evaluation for 100 rules
- **Default deny**: No matching rule = `PolicyDecision::Deny`
- **Policy field order**: `PolicyRule` fields were reordered: `mesh_id`/`where_expression` moved after `required_certifications` to keep aggregate initialization backward-compatible with existing preset definitions

---

## References

- [RFC 0028] Contract Runtime
- [RFC 0002] Capability System
- [RFC 0008] Error Model

---

**End of RFC 0029**