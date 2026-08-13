#include "deployment_contract.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <chrono>

namespace fs = std::filesystem;
namespace smo::runtime {

    namespace {

        constexpr const char* kStateFile = "contracts.state";

        static int64_t now_ns()
        {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        // FNV-1a 64-bit — deterministic across processes (unlike std::hash).
        static uint64_t fnv1a(BytesView data)
        {
            uint64_t h = 1469598103934665603ULL;
            for (size_t i = 0; i < data.size(); ++i)
            {
                h ^= static_cast<uint64_t>(data[i]);
                h *= 1099511628211ULL;
            }
            return h;
        }

        static std::string hex64(uint64_t v)
        {
            char buf[17];
            std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v)); // NOLINT
            return {buf, 16};
        }

        static Result<std::string> map_str(const ContextValue& args, const std::string& key)
        {
            if (!args.is_map())
            {
                return Error(
                    ErrorCode{ErrorCategory::Runtime, 1002, Severity::Error, RetryClass::NoRetry, Recovery::None},
                    "arguments must be a map");
            }
            auto map = args.get<std::unordered_map<std::string, std::string>>();
            auto it = map.value().find(key);
            if (it == map.value().end())
            {
                return Error(
                    ErrorCode{ErrorCategory::Runtime, 1001, Severity::Error, RetryClass::NoRetry, Recovery::None},
                    "missing argument: " + key);
            }
            return it->second;
        }

        static std::string opt_str(const ContextValue& args, const std::string& key, const std::string& def)
        {
            auto v = map_str(args, key);
            return v ? v.value() : def;
        }

        // Split a getline-style state entry into key/value around '='.
        static std::pair<std::string, std::string> split_kv(const std::string& line)
        {
            auto eq = line.find('=');
            if (eq == std::string::npos)
                return {"", ""};
            return {line.substr(0, eq), line.substr(eq + 1)};
        }

    } // namespace

    DeploymentContract::DeploymentContract(std::string data_dir)
        : NativeContract(default_metadata()), data_dir_(std::move(data_dir))
    {
        load_state();
    }

    ContractMetadata DeploymentContract::default_metadata()
    {
        ContractMetadata meta;
        meta.id = "system.contracts";
        meta.name = "Contract Deployment";
        meta.version = "0.1.0";
        meta.description = "Deploy, undeploy, status and trace for installed contracts";
        meta.required_capabilities.set(static_cast<size_t>(ContractCapability::Storage));
        return meta;
    }

    ContractCapabilities DeploymentContract::required_capabilities() const
    {
        ContractCapabilities caps;
        caps.set(static_cast<size_t>(ContractCapability::Storage));
        return caps;
    }

    Result<ContractResult> DeploymentContract::execute(const ContractInput& input, const RuntimeContext& ctx)
    {
        (void)ctx;

        if (input.method == "deploy")
            return handle_deploy(input);
        if (input.method == "undeploy")
            return handle_undeploy(input);
        if (input.method == "status")
            return handle_status(input);
        if (input.method == "list")
            return handle_list(input);
        if (input.method == "trace")
            return handle_trace(input);

        return Error(ErrorCode{ErrorCategory::Runtime, 1001, Severity::Error, RetryClass::NoRetry, Recovery::None},
                     "unknown deployment method: " + input.method);
    }

    // ── Handlers ───────────────────────────────────────────────────────

    Result<ContractResult> DeploymentContract::handle_deploy(const ContractInput& input)
    {
        auto name = map_str(input.arguments, "name");
        if (!name)
            return {name.error()};

        const std::string version = opt_str(input.arguments, "version", "0.1.0");
        const std::string publisher = opt_str(input.arguments, "publisher", "anonymous");
        const std::string description = opt_str(input.arguments, "description", "");
        const std::string entry_point = opt_str(input.arguments, "entry_point", "");

        const std::string canonical = name.value() + "|" + version + "|" + publisher;
        BytesView cdata(reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        const std::string contract_id = "ctr_" + hex64(fnv1a(cdata));

        DeployedContract dc;
        dc.contract_id = contract_id;
        dc.name = name.value();
        dc.version = version;
        dc.publisher = publisher;
        dc.description = description;
        dc.entry_point = entry_point;
        dc.state = ContractLifecycleState::Ready;
        dc.registered_at_ns = now_ns();
        dc.last_execution_at_ns = dc.registered_at_ns;
        dc.events.push_back({dc.registered_at_ns, "deployed"});
        dc.events.push_back({dc.registered_at_ns, "initialized"});
        dc.events.push_back({dc.registered_at_ns, "ready"});

        bool replacing = deployed_.find(contract_id) != deployed_.end();
        deployed_[contract_id] = std::move(dc);
        if (!replacing)
            order_.push_back(contract_id);
        persist_state();

        std::ostringstream oss;
        oss << "{"
            << "\"ok\":true,"
            << "\"contract_id\":\"" << json_escape(contract_id) << "\","
            << "\"name\":\"" << json_escape(name.value()) << "\","
            << "\"version\":\"" << json_escape(version) << "\","
            << "\"publisher\":\"" << json_escape(publisher) << "\","
            << "\"state\":\"" << describe_state(ContractLifecycleState::Ready) << "\","
            << "\"registered_at_ns\":" << deployed_[contract_id].registered_at_ns << "}";

        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> DeploymentContract::handle_undeploy(const ContractInput& input)
    {
        auto id = map_str(input.arguments, "contract_id");
        if (!id)
            return {id.error()};

        auto it = deployed_.find(id.value());
        if (it == deployed_.end())
        {
            return Error(ErrorCode{ErrorCategory::Runtime, 1004, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "contract not found: " + id.value());
        }

        auto& dc = it->second;
        if (dc.state == ContractLifecycleState::Unloaded)
        {
            std::ostringstream oss;
            oss << "{\"ok\":true,\"contract_id\":\"" << json_escape(id.value()) << "\",\"already_unloaded\":true}";
            ContractResult res;
            res.status = ContractResult::Status::Success;
            res.data = oss.str();
            return res;
        }

        dc.state = ContractLifecycleState::Unloaded;
        const int64_t ts = now_ns();
        dc.last_execution_at_ns = ts;
        dc.events.push_back({ts, "undeployed"});
        persist_state();

        std::ostringstream oss;
        oss << "{"
            << "\"ok\":true,"
            << "\"contract_id\":\"" << json_escape(id.value()) << "\","
            << "\"state\":\"unloaded\","
            << "\"undeployed_at_ns\":" << ts << "}";

        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> DeploymentContract::handle_status(const ContractInput& input)
    {
        auto id = map_str(input.arguments, "contract_id");
        if (!id)
            return {id.error()};

        auto it = deployed_.find(id.value());
        if (it == deployed_.end())
        {
            return Error(ErrorCode{ErrorCategory::Runtime, 1004, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "contract not found: " + id.value());
        }

        const auto& dc = it->second;
        std::ostringstream oss;
        oss << "{"
            << "\"ok\":true,"
            << "\"contract_id\":\"" << json_escape(dc.contract_id) << "\","
            << "\"name\":\"" << json_escape(dc.name) << "\","
            << "\"version\":\"" << json_escape(dc.version) << "\","
            << "\"publisher\":\"" << json_escape(dc.publisher) << "\","
            << "\"description\":\"" << json_escape(dc.description) << "\","
            << "\"entry_point\":\"" << json_escape(dc.entry_point) << "\","
            << "\"state\":\"" << describe_state(dc.state) << "\","
            << "\"registered_at_ns\":" << dc.registered_at_ns << ","
            << "\"last_execution_at_ns\":" << dc.last_execution_at_ns << "}";

        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> DeploymentContract::handle_list(const ContractInput& input)
    {
        (void)input;

        std::ostringstream oss;
        oss << "{\"ok\":true,\"contracts\":[";
        bool first = true;
        for (const auto& id : order_)
        {
            auto it = deployed_.find(id);
            if (it == deployed_.end())
                continue;
            const auto& dc = it->second;
            if (!first)
                oss << ",";
            first = false;
            oss << "{"
                << "\"contract_id\":\"" << json_escape(dc.contract_id) << "\","
                << "\"name\":\"" << json_escape(dc.name) << "\","
                << "\"version\":\"" << json_escape(dc.version) << "\","
                << "\"state\":\"" << describe_state(dc.state) << "\"}";
        }
        oss << "]}";

        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> DeploymentContract::handle_trace(const ContractInput& input)
    {
        auto id = map_str(input.arguments, "contract_id");
        if (!id)
            return {id.error()};

        auto it = deployed_.find(id.value());
        if (it == deployed_.end())
        {
            return Error(ErrorCode{ErrorCategory::Runtime, 1004, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "contract not found: " + id.value());
        }

        const auto& dc = it->second;
        std::ostringstream oss;
        oss << "{\"ok\":true,\"contract_id\":\"" << json_escape(dc.contract_id) << "\",\"events\":[";
        bool first = true;
        for (const auto& [ts, label] : dc.events)
        {
            if (!first)
                oss << ",";
            first = false;
            oss << "{\"ts_ns\":" << ts << ",\"event\":\"" << json_escape(label) << "\"}";
        }
        oss << "]}";

        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    // ── Persistence ────────────────────────────────────────────────────
    // Simple line-based record format (no JSON dependency):
    //   [meta] count=N
    //   [start] <contract_id>
    //   id=<contract_id>
    //   name=<escaped>
    //   version=<escaped>
    //   publisher=<escaped>
    //   description=<escaped>
    //   entry_point=<escaped>
    //   state=<int>
    //   registered_at_ns=<int>
    //   last_execution_at_ns=<int>
    //   event=<int-ts>,<escaped label>
    //   [end]
    void DeploymentContract::load_state()
    {
        deployed_.clear();
        order_.clear();

        if (data_dir_.empty())
            return;

        fs::path path = fs::path(data_dir_) / kStateFile;
        std::ifstream in(path);
        if (!in)
            return;

        DeployedContract current;
        bool in_record = false;
        std::string line;
        while (std::getline(in, line))
        {
            if (line == "[start]")
            {
                in_record = true;
                current = DeployedContract{};
                continue;
            }
            if (line == "[end]")
            {
                if (in_record && !current.contract_id.empty())
                {
                    bool is_new = deployed_.find(current.contract_id) == deployed_.end();
                    deployed_[current.contract_id] = current;
                    if (is_new)
                        order_.push_back(current.contract_id);
                }
                in_record = false;
                continue;
            }
            if (!in_record)
                continue;

            auto [key, value] = split_kv(line);
            if (key == "id")
                current.contract_id = value;
            else if (key == "name")
                current.name = value;
            else if (key == "version")
                current.version = value;
            else if (key == "publisher")
                current.publisher = value;
            else if (key == "description")
                current.description = value;
            else if (key == "entry_point")
                current.entry_point = value;
            else if (key == "state")
                current.state = static_cast<ContractLifecycleState>(std::stoi(value));
            else if (key == "registered_at_ns")
                current.registered_at_ns = std::stoll(value);
            else if (key == "last_execution_at_ns")
                current.last_execution_at_ns = std::stoll(value);
            else if (key == "event")
            {
                auto comma = value.find(',');
                if (comma != std::string::npos)
                {
                    int64_t ts = std::stoll(value.substr(0, comma));
                    current.events.push_back({ts, value.substr(comma + 1)});
                }
            }
        }
    }

    void DeploymentContract::persist_state()
    {
        if (data_dir_.empty())
            return;

        std::error_code ec;
        fs::create_directories(data_dir_, ec);

        fs::path path = fs::path(data_dir_) / kStateFile;
        std::ofstream out(path, std::ios::trunc);
        if (!out)
            return;

        out << "[meta] count=" << deployed_.size() << "\n";
        for (const auto& id : order_)
        {
            auto it = deployed_.find(id);
            if (it == deployed_.end())
                continue;
            const auto& dc = it->second;
            out << "[start]\n";
            out << "id=" << dc.contract_id << "\n";
            out << "name=" << dc.name << "\n";
            out << "version=" << dc.version << "\n";
            out << "publisher=" << dc.publisher << "\n";
            out << "description=" << dc.description << "\n";
            out << "entry_point=" << dc.entry_point << "\n";
            out << "state=" << static_cast<int>(dc.state) << "\n";
            out << "registered_at_ns=" << dc.registered_at_ns << "\n";
            out << "last_execution_at_ns=" << dc.last_execution_at_ns << "\n";
            for (const auto& [ts, label] : dc.events)
            {
                out << "event=" << ts << "," << label << "\n";
            }
            out << "[end]\n";
        }
    }

    std::string DeploymentContract::json_escape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        for (char c : s)
        {
            switch (c)
            {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
            }
        }
        return out;
    }

    std::string DeploymentContract::describe_state(ContractLifecycleState s)
    {
        switch (s)
        {
        case ContractLifecycleState::Registered:
            return "registered";
        case ContractLifecycleState::Loaded:
            return "loaded";
        case ContractLifecycleState::Initialized:
            return "initialized";
        case ContractLifecycleState::Ready:
            return "ready";
        case ContractLifecycleState::Idle:
            return "idle";
        case ContractLifecycleState::Unloaded:
            return "unloaded";
        case ContractLifecycleState::LoadFailed:
            return "failed";
        case ContractLifecycleState::InitFailed:
            return "init_failed";
        case ContractLifecycleState::InitTimeout:
            return "init_timeout";
        case ContractLifecycleState::CrashLoop:
            return "crash_loop";
        }
        return "unknown";
    }

} // namespace smo::runtime