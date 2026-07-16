#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"

namespace smo::contract::native {

// ===========================================================================
// Workflow Contracts
// ===========================================================================

enum class WorkflowOpcode : uint8_t {
    DEPLOY        = 0x01,
    UNDEPLOY      = 0x02,
    START         = 0x03,
    STOP          = 0x04,
    STATUS        = 0x05,
    LOG           = 0x06,
    SCALE         = 0x07,
    ROLLBACK      = 0x08,
    UPGRADE       = 0x09,
    VALIDATE      = 0x0A,
};

struct WorkflowDefinition {
    std::string name;
    std::string version;
    std::string description;
    
    struct Step {
        std::string name;
        std::string contract_id;
        std::unordered_map<std::string, std::string> params;
        std::vector<std::string> depends_on;
        bool required = true;
        int32_t timeout_ms = 30000;
        int32_t retry_count = 3;
        std::string on_failure;  // stop, continue, rollback
        std::unordered_map<std::string, std::string> env;
    };
    
    std::vector<Step> steps;
    
    struct WorkflowConfig {
        int32_t max_parallel = 4;
        int32_t timeout_ms = 3600000;  // 1 hour
        bool rollback_on_failure = true;
        std::string on_success;   // continue, notify, cleanup
        std::string on_failure;   // rollback, notify, pause
    } config;
};

struct WorkflowDeployRequest {
    std::string workflow_id;
    std::string workflow_definition;  // YAML/JSON
    std::unordered_map<std::string, std::string> parameters;
    bool dry_run = false;
    std::string target_mesh;
};

struct WorkflowDeployResponse {
    std::string workflow_instance_id;
    std::string trace_id;
    bool deployed = false;
    std::vector<std::string> step_ids;
};

struct WorkflowStartRequest {
    std::string workflow_instance_id;
    std::unordered_map<std::string, std::string> parameters;
    bool async = true;
};

struct WorkflowStartResponse {
    std::string execution_id;
    std::string trace_id;
    bool started = false;
};

struct WorkflowStopRequest {
    std::string workflow_instance_id;
    bool force = false;
    std::string reason;
};

struct WorkflowStopResponse {
    bool stopped = false;
    std::string message;
    std::vector<std::string> stopped_steps;
};

struct WorkflowStatusRequest {
    std::string workflow_instance_id;
    bool include_logs = false;
    int log_lines = 100;
};

struct WorkflowStatusResponse {
    std::string workflow_instance_id;
    std::string status;  // pending, running, completed, failed, cancelled
    std::string current_step;
    int32_t progress_percent = 0;
    int64_t started_ns = 0;
    int64_t estimated_completion_ns = 0;
    
    struct StepStatus {
        std::string step_id;
        std::string name;
        std::string status;  // pending, running, completed, failed, skipped
        int64_t started_ns = 0;
        int64_t completed_ns = 0;
        int32_t retry_count = 0;
        std::string error;
        std::string output;
    };
    std::vector<StepStatus> steps;
    
    struct WorkflowMetrics {
        int64_t elapsed_ms = 0;
        int32_t steps_completed = 0;
        int32_t steps_total = 0;
        int32_t steps_failed = 0;
        int32_t retries = 0;
    } metrics;
};

struct WorkflowLogRequest {
    std::string workflow_instance_id;
    std::optional<std::string> step_id;
    int32_t lines = 100;
    bool follow = false;
};

struct WorkflowLogResponse {
    struct LogEntry {
        int64_t timestamp_ns;
        std::string level;  // debug, info, warn, error
        std::string step_id;
        std::string message;
    };
    std::vector<LogEntry> logs;
    bool has_more = false;
};

struct WorkflowScaleRequest {
    std::string workflow_instance_id;
    std::string step_name;
    int32_t replicas;
};

struct WorkflowScaleResponse {
    bool scaled = false;
    int32_t old_replicas = 0;
    int32_t new_replicas = 0;
};

struct WorkflowRollbackRequest {
    std::string workflow_instance_id;
    std::optional<std::string> step_id;
    bool force = false;
};

struct WorkflowRollbackResponse {
    bool rolled_back = false;
    std::vector<std::string> rolled_back_steps;
    std::string message;
};

struct WorkflowUpgradeRequest {
    std::string workflow_instance_id;
    std::string new_version;
    bool zero_downtime = true;
    int32_t max_surge = 1;
    int32_t max_unavailable = 0;
};

struct WorkflowUpgradeResponse {
    bool upgraded = false;
    std::string old_version;
    std::string new_version;
    std::string trace_id;
};

struct WorkflowValidateRequest {
    std::string workflow_definition;  // YAML/JSON
    bool check_dependencies = true;
    bool check_resources = true;
};

struct WorkflowValidateResponse {
    bool valid = false;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<std::string> missing_dependencies;
    std::unordered_map<std::string, int32_t> resource_estimates;
};

} // namespace smo::contract::native