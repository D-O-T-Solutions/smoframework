#include "policy_federation.hpp"

#include <core/runtime/telemetry.hpp>
#include <storage/policy_store/policy_store.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace smo::federation {

static int64_t now_ns()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

// ============================================================================
// PolicyDelta
// ============================================================================

Bytes PolicyDelta::serialize() const
{
    Bytes out;
    auto write_string = [&out](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    write_string(mesh_id);

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((version >> (i * 8)) & 0xFF));

    uint32_t added_count = static_cast<uint32_t>(added_policies.size());
    out.push_back(static_cast<uint8_t>((added_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((added_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((added_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(added_count & 0xFF));
    for (const auto& policy : added_policies)
    {
        write_string(policy.name);
        write_string(policy.description);
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(policy.rules.size() & 0xFF));
        for (const auto& rule : policy.rules)
        {
            write_string(rule.name);
            write_string(rule.description);
            for (int i = 3; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((rule.priority >> (i * 8)) & 0xFF));
            // Simplified: only serialize required capabilities
            uint32_t caps = static_cast<uint32_t>(rule.required_capabilities.size());
            out.push_back(static_cast<uint8_t>((caps >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((caps >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((caps >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(caps & 0xFF));
            for (const auto& cap : rule.required_capabilities)
            {
                write_string(cap);
            }
            out.push_back(static_cast<uint8_t>(rule.effect));
            write_string(rule.mesh_id);
            write_string(rule.where_expression);
        }
        write_string(policy.version);
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((policy.created_at >> (i * 8)) & 0xFF));
        write_string(policy.created_by);
    }

    uint32_t removed_count = static_cast<uint32_t>(removed_policies.size());
    out.push_back(static_cast<uint8_t>((removed_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((removed_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((removed_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(removed_count & 0xFF));
    for (const auto& name : removed_policies)
    {
        write_string(name);
    }

    uint32_t updated_count = static_cast<uint32_t>(updated_policies.size());
    out.push_back(static_cast<uint8_t>((updated_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((updated_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((updated_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(updated_count & 0xFF));
    for (const auto& policy : updated_policies)
    {
        write_string(policy.name);
        write_string(policy.description);
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((policy.rules.size() >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(policy.rules.size() & 0xFF));
        for (const auto& rule : policy.rules)
        {
            write_string(rule.name);
            write_string(rule.description);
            for (int i = 3; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((rule.priority >> (i * 8)) & 0xFF));
            uint32_t caps = static_cast<uint32_t>(rule.required_capabilities.size());
            out.push_back(static_cast<uint8_t>((caps >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((caps >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((caps >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(caps & 0xFF));
            for (const auto& cap : rule.required_capabilities)
            {
                write_string(cap);
            }
            out.push_back(static_cast<uint8_t>(rule.effect));
            write_string(rule.mesh_id);
            write_string(rule.where_expression);
        }
        write_string(policy.version);
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((policy.created_at >> (i * 8)) & 0xFF));
        write_string(policy.created_by);
    }

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));

    return out;
}

Result<PolicyDelta> PolicyDelta::deserialize(BytesView data)
{
    PolicyDelta delta;
    size_t offset = 0;

    auto read_string = [&data, &offset](std::string& s) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 1, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 2, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string data", __FILE__, __LINE__);
        s.assign(reinterpret_cast<const char*>(data.data() + offset), len);
        offset += len;
        return {};
    };

    auto res = read_string(delta.mesh_id);
    if (!res) return res.error();

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 3, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated version", __FILE__, __LINE__);
    delta.version = 0;
    for (int i = 0; i < 8; ++i)
        delta.version = (delta.version << 8) | data[offset++];

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 4, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated added count", __FILE__, __LINE__);
    uint32_t added_count = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    delta.added_policies.reserve(added_count);
    for (uint32_t i = 0; i < added_count; ++i)
    {
        acl::PolicySet policy;
        res = read_string(policy.name);
        if (!res) return res.error();
        res = read_string(policy.description);
        if (!res) return res.error();

        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 5, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated rules count", __FILE__, __LINE__);
        uint32_t rules_count = (static_cast<uint32_t>(data[offset]) << 24) |
                               (static_cast<uint32_t>(data[offset + 1]) << 16) |
                               (static_cast<uint32_t>(data[offset + 2]) << 8) |
                               static_cast<uint32_t>(data[offset + 3]);
        offset += 4;

        policy.rules.reserve(rules_count);
        for (uint32_t j = 0; j < rules_count; ++j)
        {
            acl::PolicyRule rule;
            res = read_string(rule.name);
            if (!res) return res.error();
            res = read_string(rule.description);
            if (!res) return res.error();

            if (offset + 4 > data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 6, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated priority", __FILE__, __LINE__);
            rule.priority = 0;
            for (int k = 0; k < 4; ++k)
                rule.priority = (rule.priority << 8) | data[offset++];

            if (offset + 4 > data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 7, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated caps count", __FILE__, __LINE__);
            uint32_t caps_count = (static_cast<uint32_t>(data[offset]) << 24) |
                                  (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                  (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                  static_cast<uint32_t>(data[offset + 3]);
            offset += 4;

            rule.required_capabilities.reserve(caps_count);
            for (uint32_t k = 0; k < caps_count; ++k)
            {
                std::string cap;
                res = read_string(cap);
                if (!res) return res.error();
                rule.required_capabilities.push_back(std::move(cap));
            }

            if (offset >= data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 8, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated effect", __FILE__, __LINE__);
            rule.effect = static_cast<acl::PolicyDecision>(data[offset++]);

            res = read_string(rule.mesh_id);
            if (!res) return res.error();
            res = read_string(rule.where_expression);
            if (!res) return res.error();

            policy.rules.push_back(std::move(rule));
        }

        res = read_string(policy.version);
        if (!res) return res.error();

        if (offset + 8 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 9, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated created_at", __FILE__, __LINE__);
        policy.created_at = 0;
        for (int k = 0; k < 8; ++k)
            policy.created_at = (policy.created_at << 8) | data[offset++];

        res = read_string(policy.created_by);
        if (!res) return res.error();

        delta.added_policies.push_back(std::move(policy));
    }

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 10, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated removed count", __FILE__, __LINE__);
    uint32_t removed_count = (static_cast<uint32_t>(data[offset]) << 24) |
                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                             static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    delta.removed_policies.reserve(removed_count);
    for (uint32_t i = 0; i < removed_count; ++i)
    {
        std::string name;
        res = read_string(name);
        if (!res) return res.error();
        delta.removed_policies.push_back(std::move(name));
    }

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 11, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated updated count", __FILE__, __LINE__);
    uint32_t updated_count = (static_cast<uint32_t>(data[offset]) << 24) |
                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                             static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    delta.updated_policies.reserve(updated_count);
    for (uint32_t i = 0; i < updated_count; ++i)
    {
        acl::PolicySet policy;
        res = read_string(policy.name);
        if (!res) return res.error();
        res = read_string(policy.description);
        if (!res) return res.error();

        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 12, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated rules count", __FILE__, __LINE__);
        uint32_t rules_count = (static_cast<uint32_t>(data[offset]) << 24) |
                               (static_cast<uint32_t>(data[offset + 1]) << 16) |
                               (static_cast<uint32_t>(data[offset + 2]) << 8) |
                               static_cast<uint32_t>(data[offset + 3]);
        offset += 4;

        policy.rules.reserve(rules_count);
        for (uint32_t j = 0; j < rules_count; ++j)
        {
            acl::PolicyRule rule;
            res = read_string(rule.name);
            if (!res) return res.error();
            res = read_string(rule.description);
            if (!res) return res.error();

            if (offset + 4 > data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 13, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated priority", __FILE__, __LINE__);
            rule.priority = 0;
            for (int k = 0; k < 4; ++k)
                rule.priority = (rule.priority << 8) | data[offset++];

            if (offset + 4 > data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 14, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated caps count", __FILE__, __LINE__);
            uint32_t caps_count = (static_cast<uint32_t>(data[offset]) << 24) |
                                  (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                  (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                  static_cast<uint32_t>(data[offset + 3]);
            offset += 4;

            rule.required_capabilities.reserve(caps_count);
            for (uint32_t k = 0; k < caps_count; ++k)
            {
                std::string cap;
                res = read_string(cap);
                if (!res) return res.error();
                rule.required_capabilities.push_back(std::move(cap));
            }

            if (offset >= data.size())
                return Error(ErrorCode(ErrorCategory::Serialization, 15, Severity::Error,
                                       RetryClass::NoRetry, Recovery::None), "Truncated effect", __FILE__, __LINE__);
            rule.effect = static_cast<acl::PolicyDecision>(data[offset++]);

            res = read_string(rule.mesh_id);
            if (!res) return res.error();
            res = read_string(rule.where_expression);
            if (!res) return res.error();

            policy.rules.push_back(std::move(rule));
        }

        res = read_string(policy.version);
        if (!res) return res.error();

        if (offset + 8 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 16, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated created_at", __FILE__, __LINE__);
        policy.created_at = 0;
        for (int k = 0; k < 8; ++k)
            policy.created_at = (policy.created_at << 8) | data[offset++];

        res = read_string(policy.created_by);
        if (!res) return res.error();

        delta.updated_policies.push_back(std::move(policy));
    }

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 17, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated timestamp", __FILE__, __LINE__);
    delta.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        delta.timestamp = (delta.timestamp << 8) | data[offset++];

    return delta;
}

// ============================================================================
// TrustAnchorDelta
// ============================================================================

Bytes TrustAnchorDelta::serialize() const
{
    Bytes out;
    auto write_string = [&out](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    auto write_bytes = [&out](const Bytes& b) {
        uint32_t len = static_cast<uint32_t>(b.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), b.begin(), b.end());
    };

    write_string(mesh_id);

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((version >> (i * 8)) & 0xFF));

    uint32_t added_count = static_cast<uint32_t>(added_anchors.size());
    out.push_back(static_cast<uint8_t>((added_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((added_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((added_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(added_count & 0xFF));
    for (const auto& anchor : added_anchors)
    {
        auto cert_data = anchor.serialize();
        write_bytes(cert_data);
    }

    uint32_t removed_count = static_cast<uint32_t>(removed_anchor_fingerprints.size());
    out.push_back(static_cast<uint8_t>((removed_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((removed_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((removed_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(removed_count & 0xFF));
    for (const auto& fp : removed_anchor_fingerprints)
    {
        write_string(fp);
    }

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));

    return out;
}

Result<TrustAnchorDelta> TrustAnchorDelta::deserialize(BytesView data)
{
    TrustAnchorDelta delta;
    size_t offset = 0;

    auto read_string = [&data, &offset](std::string& s) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 1, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 2, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string data", __FILE__, __LINE__);
        s.assign(reinterpret_cast<const char*>(data.data() + offset), len);
        offset += len;
        return {};
    };

    auto read_bytes = [&data, &offset](Bytes& b) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 3, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 4, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes data", __FILE__, __LINE__);
        b.assign(data.data() + offset, data.data() + offset + len);
        offset += len;
        return {};
    };

    auto res = read_string(delta.mesh_id);
    if (!res) return res.error();

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated version", __FILE__, __LINE__);
    delta.version = 0;
    for (int i = 0; i < 8; ++i)
        delta.version = (delta.version << 8) | data[offset++];

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 6, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated added count", __FILE__, __LINE__);
    uint32_t added_count = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    delta.added_anchors.reserve(added_count);
    for (uint32_t i = 0; i < added_count; ++i)
    {
        Bytes cert_blob;
        res = read_bytes(cert_blob);
        if (!res) return res.error();
        auto cert_result = Certificate::deserialize(cert_blob);
        if (!cert_result) return cert_result.error();
        delta.added_anchors.push_back(std::move(cert_result.value()));
    }

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 7, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated removed count", __FILE__, __LINE__);
    uint32_t removed_count = (static_cast<uint32_t>(data[offset]) << 24) |
                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                             static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    delta.removed_anchor_fingerprints.reserve(removed_count);
    for (uint32_t i = 0; i < removed_count; ++i)
    {
        std::string fp;
        res = read_string(fp);
        if (!res) return res.error();
        delta.removed_anchor_fingerprints.push_back(std::move(fp));
    }

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 8, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated timestamp", __FILE__, __LINE__);
    delta.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        delta.timestamp = (delta.timestamp << 8) | data[offset++];

    return delta;
}

// ============================================================================
// PolicyFederation
// ============================================================================

PolicyFederation::PolicyFederation(const Config& config, acl::PolicyEngine& local_policy_engine)
    : config_(config), local_policy_engine_(local_policy_engine)
{
}

Result<void> PolicyFederation::initialize()
{
    return {};
}

void PolicyFederation::shutdown()
{
    remote_meshes_.clear();
}

Result<void> PolicyFederation::register_remote_mesh(const std::string& mesh_id, SendDeltaFn send_fn)
{
    if (remote_meshes_.find(mesh_id) != remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 1, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh already registered: " + mesh_id, __FILE__, __LINE__);
    }

    RemoteMeshState state;
    state.mesh_id = mesh_id;
    state.send_fn = std::move(send_fn);
    state.last_policy_version = local_policy_version();
    state.last_trust_anchor_version = local_trust_anchor_version();
    state.last_sync = now_ns();

    remote_meshes_[mesh_id] = std::move(state);
    return {};
}

Result<void> PolicyFederation::unregister_remote_mesh(const std::string& mesh_id)
{
    auto it = remote_meshes_.find(mesh_id);
    if (it == remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 2, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh not registered: " + mesh_id, __FILE__, __LINE__);
    }
    remote_meshes_.erase(it);
    return {};
}

Result<void> PolicyFederation::sync_policy_to_mesh(const std::string& remote_mesh_id)
{
    auto it = remote_meshes_.find(remote_mesh_id);
    if (it == remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 3, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh not registered: " + remote_mesh_id, __FILE__, __LINE__);
    }

    auto policy_names = local_policy_engine_.list_policies();
    if (!policy_names)
    {
        return policy_names.error();
    }

    PolicyDelta delta;
    delta.mesh_id = config_.local_mesh_id;
    delta.version = local_policy_version();
    delta.timestamp = now_ns();

    for (const auto& name : policy_names.value())
    {
        auto policy = local_policy_engine_.get_policy(name);
        if (policy)
        {
            delta.added_policies.push_back(std::move(policy.value()));
        }
    }

    return send_policy_delta(remote_mesh_id, delta);
}

Result<void> PolicyFederation::sync_trust_anchors_to_mesh(const std::string& remote_mesh_id)
{
    auto it = remote_meshes_.find(remote_mesh_id);
    if (it == remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 4, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh not registered: " + remote_mesh_id, __FILE__, __LINE__);
    }

    TrustAnchorDelta delta;
    delta.mesh_id = config_.local_mesh_id;
    delta.version = local_trust_anchor_version();
    delta.timestamp = now_ns();

    delta.added_anchors = load_local_trust_anchors();

    return send_trust_anchor_delta(remote_mesh_id, delta);
}

Result<void> PolicyFederation::handle_policy_delta(const std::string& from_mesh_id, BytesView delta_data)
{
    auto delta_result = PolicyDelta::deserialize(delta_data);
    if (!delta_result)
    {
        return delta_result.error();
    }

    return apply_policy_delta(delta_result.value());
}

Result<void> PolicyFederation::handle_trust_anchor_delta(const std::string& from_mesh_id, BytesView delta_data)
{
    auto delta_result = TrustAnchorDelta::deserialize(delta_data);
    if (!delta_result)
    {
        return delta_result.error();
    }

    return apply_trust_anchor_delta(delta_result.value());
}

void PolicyFederation::tick(int64_t now_ns)
{
    last_tick_ = now_ns;

    for (auto& [mesh_id, state] : remote_meshes_)
    {
        if ((now_ns - state.last_sync) > config_.sync_interval_ns)
        {
            sync_policy_to_mesh(mesh_id);
            sync_trust_anchors_to_mesh(mesh_id);
            state.last_sync = now_ns;
        }
    }
}

uint64_t PolicyFederation::local_policy_version() const
{
    static uint64_t version = 1;
    return version++;
}

uint64_t PolicyFederation::local_trust_anchor_version() const
{
    static uint64_t version = 1;
    return version++;
}

Result<void> PolicyFederation::send_policy_delta(const std::string& remote_mesh_id, const PolicyDelta& delta)
{
    auto it = remote_meshes_.find(remote_mesh_id);
    if (it == remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 5, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh not registered: " + remote_mesh_id, __FILE__, __LINE__);
    }

    auto data = delta.serialize();
    return it->second.send_fn(remote_mesh_id, data);
}

Result<void> PolicyFederation::send_trust_anchor_delta(const std::string& remote_mesh_id, const TrustAnchorDelta& delta)
{
    auto it = remote_meshes_.find(remote_mesh_id);
    if (it == remote_meshes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 6, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Mesh not registered: " + remote_mesh_id, __FILE__, __LINE__);
    }

    auto data = delta.serialize();
    return it->second.send_fn(remote_mesh_id, data);
}

Result<void> PolicyFederation::apply_policy_delta(const PolicyDelta& delta)
{
    for (const auto& policy : delta.added_policies)
    {
        auto res = local_policy_engine_.load_policy_set(policy);
        if (!res)
        {
            std::cerr << "[policy_federation] Failed to load policy " << policy.name << ": " << res.error().message << std::endl;
        }
        else if (on_policy_change_)
        {
            on_policy_change_(delta.mesh_id, policy, true);
        }
    }

    for (const auto& name : delta.removed_policies)
    {
        if (on_policy_change_)
        {
            acl::PolicySet empty;
            empty.name = name;
            on_policy_change_(delta.mesh_id, empty, false);
        }
    }

    for (const auto& policy : delta.updated_policies)
    {
        auto res = local_policy_engine_.load_policy_set(policy);
        if (!res)
        {
            std::cerr << "[policy_federation] Failed to update policy " << policy.name << ": " << res.error().message << std::endl;
        }
        else if (on_policy_change_)
        {
            on_policy_change_(delta.mesh_id, policy, false);
        }
    }

    return {};
}

Result<void> PolicyFederation::apply_trust_anchor_delta(const TrustAnchorDelta& delta)
{
    for (const auto& anchor : delta.added_anchors)
    {
        if (on_trust_anchor_change_)
        {
            on_trust_anchor_change_(delta.mesh_id, anchor, true);
        }
    }

    for (const auto& fp : delta.removed_anchor_fingerprints)
    {
        if (on_trust_anchor_change_)
        {
            Certificate empty;
            on_trust_anchor_change_(delta.mesh_id, empty, false);
        }
    }

    return {};
}

std::vector<Certificate> PolicyFederation::load_local_trust_anchors()
{
    std::vector<Certificate> anchors;
    return anchors;
}

} // namespace smo::federation