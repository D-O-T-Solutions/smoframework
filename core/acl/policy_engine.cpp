#include "policy_engine.hpp"

#include <yaml-cpp/yaml.h>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <regex>

namespace smo::acl {

PolicyEngine::PolicyEngine() : impl_(std::make_unique<Impl>(Config{})) {}
PolicyEngine::PolicyEngine(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
PolicyEngine::~PolicyEngine() = default;

struct PolicyEngine::Impl {
    Config config;
    std::unordered_map<std::string, PolicySet> policies_;
    std::unordered_map<std::string, PolicyResult> cache_;
    std::chrono::steady_clock::time_point cache_expiry_;
    std::mutex mutex_;
    int64_t cache_ttl_ns_;

    Impl(const Config& config) : config(config), cache_ttl_ns_(config.cache_ttl_ns) {
        load_builtin_presets();
    }

    void load_builtin_presets() {
        policies_["enterprise-standard"] = presets::ENTERPRISE_STANDARD;
        policies_["readonly"] = presets::READONLY;
        policies_["backup"] = presets::BACKUP;
        policies_["incident-response"] = presets::INCIDENT_RESPONSE;
        policies_["maintenance"] = presets::MAINTENANCE;
        policies_["devops"] = presets::DEVOPS;
        policies_["compliance"] = presets::COMPLIANCE;
    }

    Result<void> load_policy_file(const std::filesystem::path& path) {
        try {
            YAML::Node doc = YAML::LoadFile(path.string());
            
            PolicySet policy_set;
            policy_set.name = doc["name"].as<std::string>();
            policy_set.description = doc["description"].as<std::string>(""),
            policy_set.version = doc["version"].as<std::string>("1.0"),
            policy_set.created_at = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            policy_set.created_by = "file";

            if (doc["rules"]) {
                for (const auto& rule_node : doc["rules"]) {
                    PolicyRule rule;
                    rule.name = rule_node["name"].as<std::string>();
                    rule.description = rule_node["description"].as<std::string>("");
                    rule.priority = rule_node["priority"].as<int32_t>(0);
                    
                    if (rule_node["requires"]) {
                        for (const auto& cap : rule_node["requires"]) {
                            rule.required_capabilities.push_back(cap.as<std::string>());
                        }
                    }
                    if (rule_node["forbids"]) {
                        for (const auto& cap : rule_node["forbids"]) {
                            rule.forbidden_capabilities.push_back(cap.as<std::string>());
                        }
                    }
                    if (rule_node["requires_role"]) {
                        for (const auto& role : rule_node["requires_role"]) {
                            rule.required_roles.push_back(role.as<std::string>());
                        }
                    }
                    if (rule_node["forbids_role"]) {
                        for (const auto& role : rule_node["forbids_role"]) {
                            rule.forbidden_roles.push_back(role.as<std::string>());
                        }
                    }
                    if (rule_node["where"]) {
                        rule.where_expression = rule_node["where"].as<std::string>();
                    }
                    if (rule_node["effect"]) {
                        std::string effect = rule_node["effect"].as<std::string>();
                        if (effect == "allow") rule.effect = PolicyDecision::Allow;
                        else if (effect == "deny") rule.effect = PolicyDecision::Deny;
                        else if (effect == "conditional") rule.effect = PolicyDecision::Conditional;
                    }
                    if (rule_node["min_trust"]) rule.min_trust_score = rule_node["min_trust"].as<int32_t>();
                    if (rule_node["max_trust"]) rule.max_trust_score = rule_node["max_trust"].as<int32_t>();
                    if (rule_node["requires_cert"]) {
                        for (const auto& cert : rule_node["requires_cert"]) {
                            rule.required_certifications.push_back(cert.as<std::string>());
                        }
                    }

                    policy_set.rules.push_back(std::move(rule));
                }
            }

            if (doc["name"]) {
                policies_[doc["name"].as<std::string>()] = std::move(policy_set);
            }

        } catch (const YAML::Exception& e) {
            return SMO_ERR_ACL(100, Error, NoRetry, None, 
                              "YAML parse error: " + std::string(e.what()));
        }

        return {};
    }

    Result<PolicyResult> evaluate_impl(const PolicyEvaluationContext& context) const {
        PolicyResult decision;
        decision.decision = PolicyDecision::Deny;
        decision.reason = "No matching policy";

        // Sort rules by priority (highest first)
        std::vector<PolicyRule> all_rules;
        for (const auto& [name, policy_set] : policies_) {
            for (const auto& rule : policy_set.rules) {
                all_rules.push_back(rule);
            }
        }
        std::sort(all_rules.begin(), all_rules.end(), 
                 [](const PolicyRule& a, const PolicyRule& b) {
                     return a.priority > b.priority;
                 });

        for (const auto& rule : all_rules) {
            if (!matches_context(rule, context)) continue;

            decision.decision = rule.effect;
            decision.reason = rule.description.empty() ? rule.name : rule.description;
            decision.matched_rules.push_back(rule.name);

            // Check capability requirements
            for (const auto& cap : rule.required_capabilities) {
                if (std::find(context.actor_capabilities.begin(), 
                             context.actor_capabilities.end(), cap) 
                    == context.actor_capabilities.end()) {
                    decision.missing_capabilities.push_back(cap);
                } else {
                    decision.required_capabilities.push_back(cap);
                }
            }

            // Check forbidden capabilities
            for (const auto& cap : rule.forbidden_capabilities) {
                if (std::find(context.actor_capabilities.begin(), 
                             context.actor_capabilities.end(), cap) 
                    != context.actor_capabilities.end()) {
                    decision.decision = PolicyDecision::Deny;
                    decision.reason = "Forbidden capability: " + cap;
                    return decision;
                }
            }

            // Check roles
            for (const auto& role : rule.required_roles) {
                if (std::find(context.actor_roles.begin(), 
                             context.actor_roles.end(), role) 
                    == context.actor_roles.end()) {
                    decision.missing_capabilities.push_back("role:" + role);
                }
            }

            // Check trust score
            if (rule.min_trust_score && context.trust_score < *rule.min_trust_score) {
                decision.decision = PolicyDecision::Deny;
                decision.reason = "Insufficient trust score";
                return decision;
            }
            if (rule.max_trust_score && context.trust_score > *rule.max_trust_score) {
                decision.decision = PolicyDecision::Deny;
                decision.reason = "Trust score too high";
                return decision;
            }

            // Check certifications
            for (const auto& cert : rule.required_certifications) {
                if (std::find(context.certifications.begin(), 
                             context.certifications.end(), cert) 
                    == context.certifications.end()) {
                    decision.decision = PolicyDecision::Deny;
                    decision.reason = "Missing certification: " + cert;
                    return decision;
                }
            }

            // Evaluate where expression if present
            if (!rule.where_expression.empty()) {
                if (!evaluate_expression(rule.where_expression, context)) {
                    continue;
                }
                decision.matched_conditions.push_back("where: " + rule.where_expression);
            }

            // If we reach here, rule matches
            decision.matched_rules.push_back(rule.name);

            // If deny, stop evaluating
            if (rule.effect == PolicyDecision::Deny) {
                return decision;
            }
            // If allow, continue checking for higher priority deny
            if (rule.effect == PolicyDecision::Allow) {
                decision.decision = PolicyDecision::Allow;
                // Continue to check for higher priority deny
            }
        }

        return decision;
    }

    bool matches_context(const PolicyRule& rule, const PolicyEvaluationContext& context) const {
        // Check mesh
        if (!rule.mesh_id.empty() && rule.mesh_id != context.mesh_id) {
            return false;
        }
        // Could add more context matching here
        return true;
    }

    bool evaluate_expression(const std::string& expr, const PolicyEvaluationContext& context) const {
        // Simple expression evaluation
        // In production, use a proper expression engine like expr-lang
        // For now, simple string matching
        return true;  // Placeholder
    }

    Result<void> load_policies(const std::string& path) {
        namespace fs = std::filesystem;
        fs::path dir(path);
        
        if (fs::is_directory(path)) {
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.path().extension() == ".yaml" || entry.path().extension() == ".yml") {
                    auto result = load_policy_file(entry.path());
                    if (!result) return result.error();
                }
            }
            return {};
        } else {
            return load_policy_file(path);
        }
    }

    Result<void> load_policy_set(const PolicySet& policy_set) {
        policies_[policy_set.name] = policy_set;
        return {};
    }

    Result<PolicyResult> evaluate(const PolicyEvaluationContext& context) const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check cache
        if (config.enable_caching) {
            auto now = std::chrono::steady_clock::now();
            if (now < cache_expiry_) {
                std::string cache_key = make_cache_key(context);
                auto it = cache_.find(cache_key);
                if (it != cache_.end()) {
                    return it->second;
                }
            }
        }

        auto decision = evaluate_impl(context);
        
        // Cache result
        if (config.enable_caching && decision) {
            std::string cache_key = make_cache_key(context);
            cache_[cache_key] = *decision;
            // TODO: implement cache eviction
        }

        return decision;
    }

    Result<bool> check_capability(const std::string& actor_id, 
                                   const std::string& capability,
                                   const std::string& target_id) const {
        PolicyEvaluationContext context;
        context.actor_id = actor_id;
        context.target_id = target_id;
        context.actor_capabilities = {capability};
        
        auto decision = evaluate(context);
        if (!decision) return decision.error();
        
        return decision.value().decision == PolicyDecision::Allow;
    }

    Result<std::vector<std::string>> get_effective_capabilities(
        const std::string& actor_id,
        const std::string& target_id) const {
        // Would need to query all capabilities and evaluate
        return std::vector<std::string>{};
    }

    Result<std::vector<std::string>> list_policies() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : policies_) {
            names.push_back(name);
        }
        return names;
    }

    Result<PolicySet> get_policy(const std::string& name) const {
        auto it = policies_.find(name);
        if (it == policies_.end()) {
            return SMO_ERR_ACL(404, Info, RetrySafe, None, "Policy not found: " + name);
        }
        return it->second;
    }

    Result<void> reload() {
        std::lock_guard<std::mutex> lock(mutex_);
        policies_.clear();
        load_builtin_presets();
        if (!config.policy_dir.empty()) {
            return load_policies(config.policy_dir);
        }
        return {};
    }

private:
    std::string make_cache_key(const PolicyEvaluationContext& context) const {
        std::string key = context.actor_id + "|" + context.target_id + "|" 
                         + context.contract_id + "|" + context.mesh_id;
        return key;
    }
};

} // namespace smo::acl