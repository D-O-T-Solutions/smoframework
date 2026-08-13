#pragma once

#include "../contract_interface.hpp"
#include "../runtime_context.hpp"
#include "../../trust/trust.hpp"
#include "../../trust/witness.hpp"

#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace smo::runtime {

    // TrustContract (RFC 0017): peer-to-peer trust scores and witness
    // attestations, exposed over the WITNESS opcode (0x2E).
    //
    // Methods (method in payload):
    //   "score"      args { node }                          → single peer score/level
    //   "status"     args {}                                → all tracked scores (JSON)
    //   "record"     args { node, outcome=success|failure|offline } → record an outcome
    //   "attest"     args { witness, subject, claimed_score } → verify & apply a witness attestation
    //   "select"     args { requester, saw_online* }        → choose a witness (RFC 0003)
    //   "anchors"    args { action=add|remove|list, node?, public_key_hex? }
    //   "digest"     args {}                                → current trust digest (gossip payload)
    //
    // The node's signer is injected by the daemon so "attest" can produce
    // signed attestations for remote peers; verification is delegated to
    // TrustManager::verify_attestation.
    class TrustContract final : public NativeContract
    {
    public:
        using Signer = std::function<Bytes(BytesView)>;

        explicit TrustContract(smo::TrustManager* tm, std::string data_dir);

        Result<ContractResult> execute(const ContractInput& input, const RuntimeContext& ctx) override;

        ContractCapabilities required_capabilities() const override;

        static ContractMetadata default_metadata();

        void set_signer(Signer signer) { signer_ = std::move(signer); }
        void set_witness_selector(smo::trust::WitnessSelector selector) { selector_ = std::move(selector); }

        void set_membership_provider(std::function<std::pair<std::vector<NodeID>, std::vector<NodeID>>()> provider)
        {
            membership_provider_ = std::move(provider);
        }

    private:
        Result<ContractResult> handle_score(const ContractInput& input);
        Result<ContractResult> handle_status(const ContractInput& input);
        Result<ContractResult> handle_record(const ContractInput& input);
        Result<ContractResult> handle_attest(const ContractInput& input);
        Result<ContractResult> handle_select(const ContractInput& input);
        Result<ContractResult> handle_anchors(const ContractInput& input);
        Result<ContractResult> handle_digest(const ContractInput& input);

        void load_state();
        void persist_state();
        static std::string json_escape(const std::string& s);
        static std::string hex(BytesView data);
        static Result<NodeID> parse_node_id(const std::string& hexstr);

        smo::TrustManager* tm_;
        std::string data_dir_;
        Signer signer_;
        smo::trust::WitnessSelector selector_;
        std::function<std::pair<std::vector<NodeID>, std::vector<NodeID>>()> membership_provider_;
    };

} // namespace smo::runtime