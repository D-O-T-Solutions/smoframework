# ── Protocol tests ────────────────────────────────────────────────────
add_executable(smo_test_protocol
    unit/protocol/test_protocol.cpp
)
target_link_libraries(smo_test_protocol PRIVATE
    smo_core smo_protocol fmt::fmt
)
smo_set_warnings(smo_test_protocol)
smo_set_optimisation(smo_test_protocol)
add_test(NAME protocol_model COMMAND smo_test_protocol)

# ── Packet crypto (P4) ────────────────────────────────────────────────
add_executable(smo_test_packet_crypto
    unit/protocol/test_packet_crypto.cpp
)
target_link_libraries(smo_test_packet_crypto PRIVATE
    smo_core smo_protocol fmt::fmt
)
smo_set_warnings(smo_test_packet_crypto)
smo_set_optimisation(smo_test_packet_crypto)
add_test(NAME packet_crypto_model COMMAND smo_test_packet_crypto)

# ── Replay enforcement (P6) ───────────────────────────────────────────
add_executable(smo_test_replay
    unit/protocol/test_replay_enforcement.cpp
)
target_link_libraries(smo_test_replay PRIVATE
    smo_core smo_protocol smo_suite1_classical fmt::fmt
)
smo_set_warnings(smo_test_replay)
smo_set_optimisation(smo_test_replay)
add_test(NAME replay_model COMMAND smo_test_replay)

# ── P7 Negative tests ────────────────────────────────────────────────
add_executable(smo_test_negative
    unit/protocol/test_negative.cpp
)
target_link_libraries(smo_test_negative PRIVATE
    smo_core smo_protocol smo_suite1_classical fmt::fmt
)
smo_set_warnings(smo_test_negative)
smo_set_optimisation(smo_test_negative)
add_test(NAME negative_model COMMAND smo_test_negative)

# ── Trust tests ───────────────────────────────────────────────────────
add_executable(smo_test_trust
    unit/core/trust/test_trust.cpp
)
target_link_libraries(smo_test_trust PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_trust)
smo_set_optimisation(smo_test_trust)
add_test(NAME trust_model COMMAND smo_test_trust)

# ── Governance tests ──────────────────────────────────────────────────
add_executable(smo_test_governance
    unit/core/governance/test_governance.cpp
)
target_link_libraries(smo_test_governance PRIVATE
    smo_core smo_suite1_classical fmt::fmt
)
smo_set_warnings(smo_test_governance)
smo_set_optimisation(smo_test_governance)
add_test(NAME governance_model COMMAND smo_test_governance)

# ── Discovery tests ───────────────────────────────────────────────────
add_executable(smo_test_discovery
    unit/core/discovery/test_discovery.cpp
)
target_link_libraries(smo_test_discovery PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_discovery)
smo_set_optimisation(smo_test_discovery)
add_test(NAME discovery_model COMMAND smo_test_discovery)

# ── Session tests ─────────────────────────────────────────────────────
add_executable(smo_test_session
    unit/core/session/test_session.cpp
)
target_link_libraries(smo_test_session PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_session)
smo_set_optimisation(smo_test_session)
add_test(NAME session_model COMMAND smo_test_session)

# ── Session security tests ────────────────────────────────────────────
add_executable(smo_test_session_security
    unit/core/session/test_session_security.cpp
)
target_link_libraries(smo_test_session_security PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_session_security)
smo_set_optimisation(smo_test_session_security)
add_test(NAME session_security_model COMMAND smo_test_session_security)

# ── Transport tests ───────────────────────────────────────────────────
add_executable(smo_test_transport
    unit/core/transport/test_transport.cpp
)
target_link_libraries(smo_test_transport PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_transport)
smo_set_optimisation(smo_test_transport)
add_test(NAME transport_model COMMAND smo_test_transport)

# ── SecureSession P2 tests (crypto context + framing) ─────────────────
add_executable(smo_test_secure_session
    unit/core/transport/test_secure_session.cpp
)
target_link_libraries(smo_test_secure_session PRIVATE
    smo_core smo_suite1_classical fmt::fmt
)
smo_set_warnings(smo_test_secure_session)
smo_set_optimisation(smo_test_secure_session)
add_test(NAME secure_session_model COMMAND smo_test_secure_session)

# ── P0-S6 E2E tests (Session Crypto Handshake + Mesh Auth Separation) ──
add_executable(smo_test_p0_s6_e2e
    unit/core/transport/test_p0_s6_e2e.cpp
)
target_link_libraries(smo_test_p0_s6_e2e PRIVATE
    smo_core smo_suite1_classical smo_protocol smo_storage smo_contract
    fmt::fmt
)
smo_set_warnings(smo_test_p0_s6_e2e)
smo_set_optimisation(smo_test_p0_s6_e2e)
target_compile_definitions(smo_test_p0_s6_e2e PRIVATE SMO_TEST=1)
add_test(NAME p0_s6_e2e COMMAND smo_test_p0_s6_e2e)

# ── High-Level Transport tests ────────────────────────────────────────
add_executable(smo_test_transport_hl
    unit/transport/test_transport_highlevel.cpp
)
target_link_libraries(smo_test_transport_hl PRIVATE
    smo_core smo_protocol smo_transport fmt::fmt
)
smo_set_warnings(smo_test_transport_hl)
smo_set_optimisation(smo_test_transport_hl)
add_test(NAME transport_highlevel COMMAND smo_test_transport_hl)

# ── FSM tests ────────────────────────────────────────────────────────
add_executable(smo_test_fsm
    unit/core/fsm/test_fsm.cpp
)
target_link_libraries(smo_test_fsm PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_fsm)
smo_set_optimisation(smo_test_fsm)
add_test(NAME fsm_model COMMAND smo_test_fsm)

# ── MeshFSM tests ────────────────────────────────────────────────────
add_executable(smo_test_mesh_fsm
    unit/core/mesh/test_mesh_fsm.cpp
)
target_link_libraries(smo_test_mesh_fsm PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_mesh_fsm)
smo_set_optimisation(smo_test_mesh_fsm)
add_test(NAME mesh_fsm_model COMMAND smo_test_mesh_fsm)

# ── Certificate tests ────────────────────────────────────────────────
add_executable(smo_test_certificate
    unit/core/certificate/test_certificate.cpp
)
target_link_libraries(smo_test_certificate PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_certificate)
smo_set_optimisation(smo_test_certificate)
add_test(NAME certificate_model COMMAND smo_test_certificate)

# ── Identity tests ───────────────────────────────────────────────────
add_executable(smo_test_identity
    unit/core/identity/test_identity.cpp
)
target_link_libraries(smo_test_identity PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_identity)
smo_set_optimisation(smo_test_identity)
add_test(NAME identity_model COMMAND smo_test_identity)

# ── Storage store tests ─────────────────────────────────────────────
add_executable(smo_test_storage_stores
    unit/storage/test_storage_stores.cpp
)
target_link_libraries(smo_test_storage_stores PRIVATE
    smo_core smo_protocol smo_storage fmt::fmt
)
smo_set_warnings(smo_test_storage_stores)
smo_set_optimisation(smo_test_storage_stores)
add_test(NAME storage_stores COMMAND smo_test_storage_stores)

# ── Storage tests ────────────────────────────────────────────────────
add_executable(smo_test_storage
    unit/core/storage/test_storage.cpp
)
target_link_libraries(smo_test_storage PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_storage)
smo_set_optimisation(smo_test_storage)
add_test(NAME storage_model COMMAND smo_test_storage)

# ── Crypto tests ─────────────────────────────────────────────────────
add_executable(smo_test_crypto
    unit/core/crypto/test_crypto.cpp
)
target_link_libraries(smo_test_crypto PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_crypto)
smo_set_optimisation(smo_test_crypto)
add_test(NAME crypto_model COMMAND smo_test_crypto)

# ── Recovery package tests (P0-EX RecoveryDomain format v1) ─────────
add_executable(smo_test_recovery_package
    unit/core/genesis/test_recovery_package.cpp
)
target_link_libraries(smo_test_recovery_package PRIVATE
    smo_genesis smo_core fmt::fmt
)
smo_set_warnings(smo_test_recovery_package)
smo_set_optimisation(smo_test_recovery_package)
add_test(NAME recovery_package_model COMMAND smo_test_recovery_package)

# ── Shamir SSS tests (C8) ───────────────────────────────────────────
add_executable(smo_test_shamir
    unit/core/crypto/test_shamir.cpp
)
target_link_libraries(smo_test_shamir PRIVATE
    smo_genesis smo_core fmt::fmt
)
smo_set_warnings(smo_test_shamir)
smo_set_optimisation(smo_test_shamir)
add_test(NAME shamir_model COMMAND smo_test_shamir)

# ── Error model tests ────────────────────────────────────────────────
add_executable(smo_test_error
    unit/core/errors/test_error.cpp
)
target_link_libraries(smo_test_error PRIVATE
    smo_core fmt::fmt
)
smo_set_warnings(smo_test_error)
smo_set_optimisation(smo_test_error)
add_test(NAME error_model COMMAND smo_test_error)

# ── EventStore tests ──────────────────────────────────────────────────
add_executable(smo_test_event_store
    unit/core/runtime/test_event_store.cpp
)
target_link_libraries(smo_test_event_store PRIVATE
    smo_runtime smo_core smo_storage fmt::fmt
)
smo_set_warnings(smo_test_event_store)
smo_set_optimisation(smo_test_event_store)
add_test(NAME event_store_model COMMAND smo_test_event_store)

# ── RuntimeContext tests ──────────────────────────────────────────────
add_executable(smo_test_runtime_context
    unit/core/runtime/test_runtime_context.cpp
)
target_link_libraries(smo_test_runtime_context PRIVATE
    smo_runtime smo_core smo_acl fmt::fmt
)
smo_set_warnings(smo_test_runtime_context)
smo_set_optimisation(smo_test_runtime_context)
add_test(NAME runtime_context_model COMMAND smo_test_runtime_context)

# ── HistoryService tests ──────────────────────────────────────────────
add_executable(smo_test_history
    unit/core/runtime/test_history.cpp
)
target_link_libraries(smo_test_history PRIVATE
    smo_runtime smo_core fmt::fmt
)
smo_set_warnings(smo_test_history)
smo_set_optimisation(smo_test_history)
add_test(NAME history_model COMMAND smo_test_history)

# ── ExecutionEngine tests ─────────────────────────────────────────────
add_executable(smo_test_execution_engine
    unit/core/runtime/test_execution_engine.cpp
)
target_link_libraries(smo_test_execution_engine PRIVATE
    smo_runtime smo_core fmt::fmt
)
smo_set_warnings(smo_test_execution_engine)
smo_set_optimisation(smo_test_execution_engine)
add_test(NAME execution_engine_model COMMAND smo_test_execution_engine)

# ── Scheduler tests ───────────────────────────────────────────────────
add_executable(smo_test_scheduler
    unit/core/runtime/test_scheduler.cpp
)
target_link_libraries(smo_test_scheduler PRIVATE
    smo_runtime smo_core fmt::fmt
)
smo_set_warnings(smo_test_scheduler)
smo_set_optimisation(smo_test_scheduler)
add_test(NAME scheduler_model COMMAND smo_test_scheduler)

# ── Contract tests ──────────────────────────────────────────────────
add_executable(smo_test_contract
    unit/core/contract/test_contract.cpp
)
target_link_libraries(smo_test_contract PRIVATE
    smo_core smo_contract smo_blake3_provider fmt::fmt
)
smo_set_warnings(smo_test_contract)
smo_set_optimisation(smo_test_contract)
add_test(NAME contract_model COMMAND smo_test_contract)

# ── Protocol Compliance Tests (PCT-001 through PCT-017) ────────────
add_executable(smo_pct
    unit/protocol/test_pct.cpp
)
target_link_libraries(smo_pct PRIVATE
    smo_runtime smo_core smo_contract smo_protocol smo_storage
    smo_suite1_classical smo_suite2_modern
    fmt::fmt
)
if(WITH_PQC)
    target_link_libraries(smo_pct PRIVATE smo_suite3_purepqc)
endif()
smo_set_warnings(smo_pct)
smo_set_optimisation(smo_pct)
target_compile_definitions(smo_pct PRIVATE SMO_TEST=1)
smo_link_dependencies(smo_pct)
add_test(NAME protocol_compliance COMMAND smo_pct)

# ── Legacy stubs (placeholder tests — no op) ─────────────────────────
# Each stub has its own main(); they must be separate executables.
macro(smo_add_legacy_stub name source)
    add_executable(smo_stub_${name} ${source})
    smo_set_warnings(smo_stub_${name})
    smo_set_optimisation(smo_stub_${name})
    add_test(NAME ${name} COMMAND smo_stub_${name})
endmacro()

smo_add_legacy_stub(core     unit/core_test.cpp)
smo_add_legacy_stub(protocol unit/protocol_test.cpp)
smo_add_legacy_stub(compiler unit/compiler_test.cpp)

# Future test suites (placeholders for now):
# add_subdirectory(integration)
# add_subdirectory(mesh)
# add_subdirectory(chaos)
# add_subdirectory(replay)
# add_subdirectory(adversarial)
