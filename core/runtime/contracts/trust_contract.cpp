#include "trust_contract.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <chrono>
#include <cmath>

namespace fs = std::filesystem;
namespace smo::runtime {

    namespace {

        constexpr const char* kStateFile = "trust.state";

        static int64_t now_ns()
        {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
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

        static std::string json_num(double v)
        {
            if (std::isnan(v) || std::isinf(v))
                return "0.0";
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.4f", v);
            return {buf};
        }

    } // namespace

    TrustContract::TrustContract(smo::TrustManager* tm, std::string data_dir)
        : NativeContract(default_metadata()), tm_(tm), data_dir_(std::move(data_dir))
    {
        load_state();
    }

    ContractMetadata TrustContract::default_metadata()
    {
        ContractMetadata meta;
        meta.id = "system.trust";
        meta.name = "Peer Trust & Witness";
        meta.version = "0.1.0";
        meta.description = "Witness selection, peer trust scores and attestations (RFC 0017)";
        meta.required_capabilities.set(static_cast<size_t>(ContractCapability::Audit));
        return meta;
    }

    ContractCapabilities TrustContract::required_capabilities() const
    {
        ContractCapabilities caps;
        caps.set(static_cast<size_t>(ContractCapability::Audit));
        return caps;
    }

    Result<ContractResult> TrustContract::execute(const ContractInput& input, const RuntimeContext& ctx)
    {
        (void)ctx;

        if (input.method == "score")
            return handle_score(input);
        if (input.method == "status")
            return handle_status(input);
        if (input.method == "record")
            return handle_record(input);
        if (input.method == "attest")
            return handle_attest(input);
        if (input.method == "select")
            return handle_select(input);
        if (input.method == "anchors")
            return handle_anchors(input);
        if (input.method == "digest")
            return handle_digest(input);

        return Error(ErrorCode{ErrorCategory::Runtime, 1001, Severity::Error, RetryClass::NoRetry, Recovery::None},
                     "unknown trust method: " + input.method);
    }

    Result<ContractResult> TrustContract::handle_score(const ContractInput& input)
    {
        auto node = map_str(input.arguments, "node");
        if (!node)
            return {node.error()};

        auto id = parse_node_id(node.value());
        if (!id)
            return {id.error()};

        auto rec = tm_->get_record(id.value());
        ContractResult res;
        res.status = ContractResult::Status::Success;
        if (!rec)
        {
            std::ostringstream oss;
            oss << "{\"ok\":true,\"node\":\"" << json_escape(node.value()) << "\",\"score\":null,\"level\":\"None\","
                << "\"reason\":\"" << json_escape(rec.error().message) << "\"}";
            res.data = oss.str();
            return res;
        }

        const auto& ts = rec.value();
        std::ostringstream oss;
        oss << "{"
            << "\"ok\":true,"
            << "\"node\":\"" << json_escape(node.value()) << "\","
            << "\"score\":" << json_num(ts.composite) << ","
            << "\"level\":\"" << to_string(ts.level()) << "\","
            << "\"citizen\":" << json_num(ts.components.citizen) << ","
            << "\"execution\":" << json_num(ts.components.execution) << ","
            << "\"witness\":" << json_num(ts.components.witness) << ","
            << "\"consistency\":" << json_num(ts.components.consistency) << ","
            << "\"last_updated_ns\":" << ts.last_updated << "}";
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_status(const ContractInput& input)
    {
        (void)input;
        auto scores = tm_->all_scores();

        std::ostringstream oss;
        oss << "{\"ok\":true,\"count\":" << scores.size() << ",\"scores\":[";
        bool first = true;
        for (const auto& s : scores)
        {
            if (!first)
                oss << ",";
            first = false;
            oss << "{"
                << "\"node\":\"" << s.node_id.to_string() << "\","
                << "\"score\":" << json_num(s.composite) << ","
                << "\"level\":\"" << to_string(s.level()) << "\","
                << "\"witness\":" << json_num(s.components.witness) << "}";
        }
        oss << "]}";
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_record(const ContractInput& input)
    {
        auto node = map_str(input.arguments, "node");
        if (!node)
            return {node.error()};
        const std::string outcome = opt_str(input.arguments, "outcome", "success");

        auto id = parse_node_id(node.value());
        if (!id)
            return {id.error()};

        const int64_t ts = now_ns();
        if (outcome == "failure")
        {
            tm_->record_failure(id.value(), 1.0, ts);
        }
        else if (outcome == "offline")
        {
            tm_->record_offline(id.value(), ts);
        }
        else
        {
            tm_->record_success(id.value(), 1.0, ts);
        }
        persist_state();

        std::ostringstream oss;
        oss << "{\"ok\":true,\"node\":\"" << json_escape(node.value()) << "\",\"outcome\":\"" << json_escape(outcome)
            << "\",\"updated_at_ns\":" << ts << "}";
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_attest(const ContractInput& input)
    {
        // Two directions:
        //   1. {"witness","subject","claimed_score"} → the witness signs & returns a
        //      signed attestation payload for the responder to apply.
        //   2. {"attestation_base64"} → verify & apply a previously produced payload.
        if (map_str(input.arguments, "attestation_base64"))
        {
            auto payload = map_str(input.arguments, "attestation_base64");
            // Decoded payload: witness|subject|claimed|timestamp|signature_hex
            std::istringstream ss(payload.value());
            std::string witness_hex, subject_hex, claimed_s, ts_s, sig_hex;
            std::getline(ss, witness_hex, '|');
            std::getline(ss, subject_hex, '|');
            std::getline(ss, claimed_s, '|');
            std::getline(ss, ts_s, '|');
            std::getline(ss, sig_hex, '|');

            auto witness_id = parse_node_id(witness_hex);
            auto subject_id = parse_node_id(subject_hex);
            if (!witness_id || !subject_id)
            {
                return Error(ErrorCode{ErrorCategory::Trust, 206, Severity::Error, RetryClass::NoRetry, Recovery::None},
                             "malformed attestation: bad node id");
            }

            Attestation att;
            att.witness_id = witness_id.value();
            att.subject_id = subject_id.value();
            att.claimed_score = std::strtod(claimed_s.c_str(), nullptr);
            att.timestamp = std::strtoll(ts_s.c_str(), nullptr, 10);
            if (sig_hex.size() % 2 != 0)
            {
                return Error(ErrorCode{ErrorCategory::Trust, 206, Severity::Error, RetryClass::NoRetry, Recovery::None},
                             "malformed attestation: bad signature");
            }
            for (size_t i = 0; i + 1 < sig_hex.size(); i += 2)
            {
                std::string byte = sig_hex.substr(i, 2);
                att.signature.push_back(static_cast<uint8_t>(std::strtol(byte.c_str(), nullptr, 16)));
            }

            if (auto ec = tm_->verify_attestation(att, now_ns()); !ec)
            {
                return Error(ec.error());
            }
            tm_->apply_attestation(att);
            persist_state();

            std::ostringstream oss;
            oss << "{\"ok\":true,\"witness\":\"" << json_escape(witness_hex) << "\",\"subject\":\""
                << json_escape(subject_hex) << "\",\"claimed\":" << json_num(att.claimed_score) << ",\"applied\":true}";
            ContractResult res;
            res.status = ContractResult::Status::Success;
            res.data = oss.str();
            return res;
        }

        auto witness = map_str(input.arguments, "witness");
        if (!witness)
            return {witness.error()};
        auto subject = map_str(input.arguments, "subject");
        if (!subject)
            return {subject.error()};
        auto claimed_s = map_str(input.arguments, "claimed_score");
        if (!claimed_s)
            return {claimed_s.error()};

        auto witness_id = parse_node_id(witness.value());
        auto subject_id = parse_node_id(subject.value());
        if (!witness_id || !subject_id)
        {
            return Error(ErrorCode{ErrorCategory::Trust, 206, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "malformed attestation request: bad node id");
        }

        double claimed = std::strtod(claimed_s.value().c_str(), nullptr);
        if (claimed < 0.0 || claimed > 1.0)
        {
            return Error(ErrorCode{ErrorCategory::Trust, 206, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "claimed score out of range [0,1]");
        }

        // Produce a canonical, signed attestation payload (pipe-separated, hex fields).
        const int64_t ts = now_ns();
        std::ostringstream canonical;
        canonical << witness.value() << "|" << subject.value() << "|" << claimed_s.value() << "|" << ts;

        Bytes sig;
        if (signer_)
        {
            BytesView cdata(reinterpret_cast<const uint8_t*>(canonical.str().data()), canonical.str().size());
            sig = signer_(cdata);
        }
        std::ostringstream sig_hex;
        sig_hex << hex(sig);

        std::ostringstream oss;
        oss << canonical.str() << "|" << sig_hex.str();
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_select(const ContractInput& input)
    {
        auto requester_s = map_str(input.arguments, "requester");
        if (!requester_s)
            return {requester_s.error()};

        auto requester = parse_node_id(requester_s.value());
        if (!requester)
            return {requester.error()};

        // Optional explicit peer list in "peers" (space- or comma-separated);
        // otherwise pull from the daemon-provided membership provider.
        std::vector<NodeID> all;
        std::vector<NodeID> online;
        auto explicit_peers = map_str(input.arguments, "peers");
        if (explicit_peers)
        {
            std::istringstream ss(explicit_peers.value());
            std::string tok;
            while (std::getline(ss, tok, ','))
            {
                auto id = parse_node_id(tok);
                if (id)
                    all.push_back(id.value());
            }
            online = all;
        }
        else if (membership_provider_)
        {
            auto [on, a] = membership_provider_();
            online = std::move(on);
            all = std::move(a);
        }
        else
        {
            auto scored = tm_->all_scores();
            for (const auto& s : scored)
                all.push_back(s.node_id);
            online = all;
        }

        auto candidates = smo::trust::WitnessSelector::candidates_from(*tm_, online, all);
        auto witness = selector_.select(requester.value(), NodeID{}, candidates);

        std::ostringstream oss;
        oss << "{\"ok\":true,\"requester\":\"" << json_escape(requester_s.value()) << "\",\"witness\":";
        if (witness)
            oss << "\"" << witness->to_string() << "\",\"fallback_local\":false";
        else
            oss << "null,\"fallback_local\":true";
        oss << ",\"eligible_count\":" << candidates.size() << "}";
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_anchors(const ContractInput& input)
    {
        const std::string action = opt_str(input.arguments, "action", "list");
        std::ostringstream oss;

        if (action == "add")
        {
            auto node = map_str(input.arguments, "node");
            if (!node)
                return {node.error()};
            auto id = parse_node_id(node.value());
            if (!id)
                return {id.error()};

            std::string pk_hex = opt_str(input.arguments, "public_key_hex", "");
            Bytes pk;
            if (pk_hex.size() % 2 == 0)
            {
                for (size_t i = 0; i + 1 < pk_hex.size(); i += 2)
                    pk.push_back(static_cast<uint8_t>(std::strtol(pk_hex.substr(i, 2).c_str(), nullptr, 16)));
            }

            TrustAnchor anchor;
            anchor.node_id = id.value();
            anchor.public_key = std::move(pk);
            anchor.added_at = now_ns();
            tm_->add_trust_anchor(anchor);
            persist_state();
            oss << "{\"ok\":true,\"action\":\"add\",\"node\":\"" << json_escape(node.value()) << "\"}";
        }
        else if (action == "remove")
        {
            auto node = map_str(input.arguments, "node");
            if (!node)
                return {node.error()};
            auto id = parse_node_id(node.value());
            if (!id)
                return {id.error()};
            bool removed = tm_->remove_trust_anchor(id.value());
            persist_state();
            oss << "{\"ok\":true,\"action\":\"remove\",\"node\":\"" << json_escape(node.value())
                << "\",\"removed\":" << (removed ? "true" : "false") << "}";
        }
        else
        {
            auto anchors = tm_->trust_anchors();
            oss << "{\"ok\":true,\"action\":\"list\",\"count\":" << anchors.size() << ",\"anchors\":[";
            bool first = true;
            for (const auto& a : anchors)
            {
                if (!first)
                    oss << ",";
                first = false;
                oss << "{\"node\":\"" << a.node_id.to_string() << "\",\"added_at_ns\":" << a.added_at << "}";
            }
            oss << "]}";
        }
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    Result<ContractResult> TrustContract::handle_digest(const ContractInput& input)
    {
        (void)input;
        // Local origin (responder identity supplied via ctx where available);
        // we use a zero origin digest for listing purposes.
        TrustDigest digest;
        digest.origin = {};
        digest.sequence = tm_->digest_sequence();
        digest.timestamp = now_ns();
        digest.scores = tm_->all_scores();

        std::ostringstream oss;
        oss << "{\"ok\":true,\"sequence\":" << digest.sequence << ",\"timestamp_ns\":" << digest.timestamp
            << ",\"peer_count\":" << digest.scores.size() << "}";
        ContractResult res;
        res.status = ContractResult::Status::Success;
        res.data = oss.str();
        return res;
    }

    // ── Persistence ─────────────────────────────────────────────────

    void TrustContract::load_state()
    {
        if (!tm_)
            return;
        const std::string path = data_dir_ + "/" + kStateFile;
        std::ifstream in(path, std::ios::binary);
        if (!in)
            return;
        in.seekg(0, std::ios::end);
        std::streamsize sz = in.tellg();
        in.seekg(0, std::ios::beg);
        if (sz <= 0)
            return;
        Bytes data(static_cast<size_t>(sz));
        in.read(reinterpret_cast<char*>(data.data()), sz);
        if (!in)
            return;
        auto res = smo::TrustManager::deserialize(BytesView(data));
        if (res)
        {
            *tm_ = std::move(res.value());
        }
    }

    void TrustContract::persist_state()
    {
        if (!tm_)
            return;
        const std::string path = data_dir_ + "/" + kStateFile;
        Bytes ser = tm_->serialize();
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
            return;
        out.write(reinterpret_cast<const char*>(ser.data()), static_cast<std::streamsize>(ser.size()));
    }

    std::string TrustContract::json_escape(const std::string& s)
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
                break;
            }
        }
        return out;
    }

    std::string TrustContract::hex(BytesView data)
    {
        static const char* kHex = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (uint8_t b : data)
        {
            out += kHex[b >> 4];
            out += kHex[b & 0x0F];
        }
        return out;
    }

    Result<NodeID> TrustContract::parse_node_id(const std::string& hexstr)
    {
        if (hexstr.size() != 64)
        {
            return Error(ErrorCode{ErrorCategory::Trust, 206, Severity::Error, RetryClass::NoRetry, Recovery::None},
                         "node id must be 64 hex chars, got '" + hexstr + "'");
        }
        NodeID id{};
        for (size_t i = 0; i < 32; ++i)
        {
            int hi = std::strtol(hexstr.substr(i * 2, 1).c_str(), nullptr, 16);
            int lo = std::strtol(hexstr.substr(i * 2 + 1, 1).c_str(), nullptr, 16);
            id.value[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return id;
    }

} // namespace smo::runtime