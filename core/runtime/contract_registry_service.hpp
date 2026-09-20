#pragma once

#include <core/runtime/dispatcher.hpp>
#include <core/runtime/runtime_bridge.hpp>
#include <core/runtime/middleware_pipeline.hpp>
#include <core/network/packet_dispatcher.hpp>
#include <core/mesh/mesh_manager.hpp>
#include <core/authority/authority.hpp>
#include <core/governance/governance.hpp>
#include <core/recovery/crl.hpp>
#include <core/recovery/recovery_engine.hpp>
#include <core/trust/trust.hpp>
#include <core/session/session.hpp>
#include <core/runtime/event_bus.hpp>
#include <core/runtime/output_manager.hpp>
#include <core/crypto/impl.hpp>
#include <core/errors/error.hpp>
#include <core/discovery/discovery.hpp>
#include <core/runtime/contracts/echo_contract.hpp>
#include <core/runtime/contracts/bootstrap_contract.hpp>
#include <core/runtime/contracts/join_contract.hpp>
#include <core/runtime/contracts/governance_contract.hpp>
#include <core/runtime/contracts/recovery_contract.hpp>
#include <core/runtime/contracts/file_contract.hpp>
#include <core/runtime/contracts/process_contract.hpp>
#include <core/runtime/contracts/deployment_contract.hpp>
#include <core/runtime/contracts/trust_contract.hpp>
#include <core/runtime/protocol_service.hpp>
#include <core/fsm/node_lifecycle_fsm.hpp>
#include <core/bootstrap/bootstrap_protocol.hpp>
#include <core/join/join_protocol.hpp>

#include <string>
#include <memory>
#include <functional>

namespace smo::runtime {

// ContractRegistryService: owns all contract registrations and route/packet handler wiring
class ContractRegistryService
{
public:
    struct Config
    {
        std::string data_dir;
    };

    struct Dependencies
    {
        MeshManager& mesh_manager;
        authority::MeshAuthority& authority;
        GovernanceEngine& governance_engine;
        recovery::CRL& crl;
        SessionManager& session_mgr;
        TrustManager& trust_mgr;
        recovery::RecoveryEngine& recovery_engine;
        Dispatcher& runtime_dispatcher;
        RuntimeBridge& runtime_bridge;
        MiddlewarePipeline& middleware_pipeline;
        network::PacketDispatcher& packet_dispatcher;
        NodeLifecycleFSM& node_fsm;
        ProtocolService& protocol_service;
        EventBus& event_bus;
        MembershipTable& membership;
        const CryptoProvider* crypto = nullptr;
        Identity& identity;
    };

    explicit ContractRegistryService(const Config& config, const Dependencies& deps);
    ~ContractRegistryService() = default;

    ContractRegistryService(const ContractRegistryService&) = delete;
    ContractRegistryService& operator=(const ContractRegistryService&) = delete;
    ContractRegistryService(ContractRegistryService&&) = default;
    ContractRegistryService& operator=(ContractRegistryService&&) = default;

    // Register all contracts, wire routes, and wire packet handlers
    void register_all();

    // The runtime handler for contract opcodes (exposed for PacketDispatcher registration)
    using RuntimeHandler = std::function<Result<void>(Packet&&, const Endpoint&, network::hl::Transport&)>;
    RuntimeHandler make_runtime_handler();

private:
    void register_contracts();
    void register_routes();
    void register_packet_handlers(RuntimeHandler handler);

    Config config_;
    Dependencies deps_;
};

} // namespace smo::runtime