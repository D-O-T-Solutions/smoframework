#include <core/runtime/contract_registry_service.hpp>

#include <core/runtime/runtime_kernel.hpp>
#include <core/runtime/action_executor.hpp>

#include <chrono>

namespace smo::runtime {

ContractRegistryService::ContractRegistryService(const Config& config, const Dependencies& deps)
    : config_(config)
    , deps_(deps)
{
}

void ContractRegistryService::register_all()
{
    register_contracts();
    register_routes();
    auto runtime_handler = make_runtime_handler();
    register_packet_handlers(runtime_handler);
}

void ContractRegistryService::register_contracts()
{
    // Echo (legacy, for backwards compat)
    deps_.runtime_dispatcher.register_contract("system.echo",
                                               std::make_unique<EchoContract>());

    // BootstrapContract: mesh bootstrap snapshots
    deps_.runtime_dispatcher.register_contract(
        "system.bootstrap",
        std::make_unique<BootstrapContract>(deps_.mesh_manager, deps_.authority,
                                            &deps_.governance_engine, nullptr));

    // JoinContract: node enrollment
    {
        auto rng = deps_.crypto->default_rng();
        deps_.runtime_dispatcher.register_contract(
            "system.join",
            std::make_unique<JoinContract>(deps_.crypto->hash, deps_.crypto->signer, rng));
    }

    // GovernanceContract: proposals, voting, commit
    deps_.runtime_dispatcher.register_contract(
        "system.governance",
        std::make_unique<GovernanceContract>(deps_.governance_engine, deps_.authority));

    // RecoveryContract: recovery sessions, CRL
    deps_.runtime_dispatcher.register_contract(
        "system.recovery",
        std::make_unique<RecoveryContract>(deps_.recovery_engine, &deps_.crl, deps_.governance_engine));

    // FileContract: filesystem operations
    deps_.runtime_dispatcher.register_contract("system.file",
                                               std::make_unique<FileContract>());

    // ProcessContract: process management
    deps_.runtime_dispatcher.register_contract("system.process",
                                               std::make_unique<ProcessContract>());

    // DeploymentContract: contract deploy/undeploy/status/trace lifecycle
    deps_.runtime_dispatcher.register_contract("system.contracts",
                                               std::make_unique<DeploymentContract>(config_.data_dir));

    // TrustContract (RFC 0017): peer trust scores + witness attestation/selection
    {
        auto trust_contract = std::make_unique<TrustContract>(&deps_.trust_mgr, config_.data_dir);
        trust_contract->set_signer([this](BytesView msg) {
            auto rng = deps_.crypto->default_rng();
            auto sig = deps_.crypto->signer.sign(
                msg, Bytes(deps_.identity.secret_key().begin(), deps_.identity.secret_key().end()), rng);
            if (!sig)
                return Bytes{};
            return sig.value();
        });
        trust_contract->set_membership_provider([this]() {
            std::vector<NodeID> online;
            std::vector<NodeID> all;
            for (const auto& entry : deps_.membership.peers())
            {
                all.push_back(entry.node_id);
            }
            for (const auto& entry : deps_.membership.peers_with_state(PeerState::Online))
            {
                online.push_back(entry.node_id);
            }
            return std::make_pair(std::move(online), std::move(all));
        });
        deps_.runtime_dispatcher.register_contract("system.trust", std::move(trust_contract));
    }
}

void ContractRegistryService::register_routes()
{
    // Echo
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::ECHO), "system.echo", "echo");

    // BootstrapContract
    deps_.runtime_bridge.register_route(bootstrap::kOpcodeBootstrapRequest, "system.bootstrap", "request");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::BOOTSTRAP_SNAPSHOT), "system.bootstrap",
                                        "snapshot");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::BOOTSTRAP_INFO), "system.bootstrap", "info");
    deps_.runtime_bridge.register_route(join::kOpcodeBootstrapSyncReq, "system.bootstrap", "bootstrap_sync");

    // JoinContract
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::JOIN), "system.join", "join");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::LEAVE), "system.join", "leave");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::JOIN_INFO), "system.join", "info");

    // GovernanceContract
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_PROPOSE), "system.governance", "propose");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_VOTE), "system.governance", "vote");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_COMMIT), "system.governance", "commit");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_LIST), "system.governance", "list");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_STATUS), "system.governance", "status");
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::GOV_INFO), "system.governance", "info");

    // RecoveryContract (single opcode, method in payload)
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::RECOVERY), "system.recovery", "invoke");

    // FileContract (single opcode, method in payload)
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::FILE_OP), "system.file", "invoke");

    // ProcessContract (single opcode, method in payload)
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::PROCESS), "system.process", "invoke");

    // DeploymentContract (single opcode, method in payload)
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::CONTRACT_MGMT), "system.contracts", "invoke");

    // TrustContract (single opcode, method in payload, RFC 0017)
    deps_.runtime_bridge.register_route(static_cast<uint32_t>(Opcode::WITNESS), "system.trust", "invoke");
}

void ContractRegistryService::register_packet_handlers(RuntimeHandler handler)
{
    // Node Lifecycle FSM
    deps_.node_fsm.on_event(NodeLifecycleEvent::IDENTITY_CREATED);

    // Authority node: transition to ACTIVE since it has a cert and is the mesh root
    // Note: server_cert_blob_ check is done in node_runtime.cpp, we can't access it here
    // The caller should handle this if needed

    // PacketDispatcher setup
    deps_.packet_dispatcher.set_lifecycle_fsm(&deps_.node_fsm);
    deps_.packet_dispatcher.set_gossip_engine(nullptr); // Set by caller if needed

    // Register runtime handler for all contract opcodes
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::ECHO), handler);
    deps_.packet_dispatcher.register_handler(bootstrap::kOpcodeBootstrapRequest, handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::BOOTSTRAP_SNAPSHOT), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::BOOTSTRAP_INFO), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::JOIN), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::LEAVE), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::JOIN_INFO), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_PROPOSE), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_VOTE), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_COMMIT), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_LIST), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_STATUS), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::GOV_INFO), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::RECOVERY), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::FILE_OP), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::PROCESS), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::CONTRACT_MGMT), handler);
    deps_.packet_dispatcher.register_handler(static_cast<uint32_t>(Opcode::WITNESS), handler);
    deps_.packet_dispatcher.register_handler(join::kOpcodeBootstrapSyncReq, handler);

    // Raw handler delegated to ProtocolService
    deps_.protocol_service.register_raw_handler(deps_.packet_dispatcher);
}

ContractRegistryService::RuntimeHandler ContractRegistryService::make_runtime_handler()
{
    return [this](Packet&& pkt, const Endpoint& remote, network::hl::Transport& t) -> Result<void> {
        std::string remote_str = remote.host + ":" + std::to_string(remote.port);
        std::printf("[smo-node] Packet received opcode=0x%x from %s\n", pkt.opcode_id, remote_str.c_str());

        // 1. Session lookup (if session_id present)
        const Session* session = nullptr;
        bool has_session = pkt.session_id().size() >= 16;
        if (has_session)
        {
            auto sid_res = SessionId::from_bytes(BytesView(pkt.session_id().data(), 16));
            if (sid_res)
            {
                session = deps_.session_mgr.lookup(sid_res.value());
            }
        }

        // 2. Middleware pipeline: validate + policy
        PacketContext mw_ctx;
        mw_ctx.session = session;
        auto* route = deps_.runtime_bridge.resolve(pkt.opcode_id);
        if (route)
        {
            mw_ctx.contract_id = route->contract_id;
            mw_ctx.method = route->method;
        }
        mw_ctx.payload = BytesView(pkt.payload.data(), pkt.payload.size());
        {
            char hex[16];
            std::snprintf(hex, sizeof(hex), "0x%04x", pkt.opcode_id);
            mw_ctx.opcode_hex = hex;
        }

        auto mw_res = deps_.middleware_pipeline.process(mw_ctx);
        if (!mw_res)
        {
            std::printf("[smo-node] Middleware denied: %s\n", mw_res.error().message.c_str());
            return mw_res.error();
        }
        if (mw_ctx.denied)
        {
            std::printf("[smo-node] Policy denied: %s\n", mw_ctx.deny_reason.c_str());
            return Error(ErrorCode(ErrorCategory::Session, 507, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None),
                         mw_ctx.deny_reason, __FILE__, __LINE__);
        }

        // 3. Bridge: Packet -> RuntimeKernel -> RuntimeResult
        auto original_pkt = pkt;

        // Send an error response packet back to the requester.
        auto send_error_packet = [&](const std::string& message) {
            Packet err_resp;
            err_resp.header = original_pkt.header;
            err_resp.opcode_id = original_pkt.opcode_id;
            err_resp.session_id() = original_pkt.session_id();
            err_resp.intent_id = original_pkt.intent_id;
            err_resp.timestamp() = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
            err_resp.payload.assign(message.begin(), message.end());
            (void)t.send(std::move(err_resp), remote);
        };

        auto rt_result = deps_.runtime_bridge.bridge(std::move(pkt));
        if (!rt_result)
        {
            std::printf("[smo-node] RuntimeBridge failed: %s\n", rt_result.error().message.c_str());
            send_error_packet("error: " + rt_result.error().message);
            return rt_result.error();
        }

        // 4. Execute each NextAction via ActionExecutor
        auto& next_actions = rt_result.value().next_actions;
        if (next_actions.empty())
        {
            // No async actions: deliver the contract result directly as the
            // response packet so request/response clients (CLI) get an answer.
            if (rt_result.value().output)
            {
                Packet resp;
                resp.header = original_pkt.header;
                resp.opcode_id = original_pkt.opcode_id;
                resp.session_id() = original_pkt.session_id();
                resp.intent_id = original_pkt.intent_id;
                resp.timestamp() = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();

                const auto& out = rt_result.value().output.value();
                if (!out.binary.empty())
                {
                    resp.payload = out.binary;
                }
                else
                {
                    resp.payload.assign(out.data.begin(), out.data.end());
                }

                auto send_ec = t.send(std::move(resp), remote);
                if (send_ec)
                {
                    std::printf("[smo-node] Response send failed: %s\n", send_ec.message().c_str());
                    return Error(ErrorCode(ErrorCategory::Transport,
                                           static_cast<uint16_t>(send_ec.value()), Severity::Error,
                                           RetryClass::RetrySafe, Recovery::None),
                                 "response send failed", __FILE__, __LINE__);
                }
            }
            else
            {
                std::printf("[smo-node] No next actions and no output - result: %s\n",
                            rt_result.value().output ? rt_result.value().output->data.c_str() : "(no output)");
            }
            return {};
        }

        for (auto& action : next_actions)
        {
            ActionExecutor executor(
                [&](Packet&& resp) -> Result<void> {
                    auto ec = t.send(std::move(resp), remote);
                    if (ec)
                    {
                        return Error(ErrorCode(ErrorCategory::Transport,
                                             static_cast<uint16_t>(ec.value()), Severity::Error,
                                             RetryClass::RetrySafe, Recovery::None),
                                     "ActionExecutor send failed", __FILE__, __LINE__);
                    }
                    return {};
                },
                &deps_.event_bus);

            auto exec_res = executor.execute(action, original_pkt);
            if (!exec_res)
            {
                std::printf("[smo-node] ActionExecutor failed: %s\n", exec_res.error().message.c_str());
            }
        }

        return {};
    };
}

} // namespace smo::runtime