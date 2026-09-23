#pragma once

// RFC 0022: Frozen schemas for 8 SQLite stores
// Each store has a fixed schema version and DDL that must not change without migration

#include "store_id.hpp"
#include <array>

namespace smo {

struct SchemaDefinition
{
    StoreID store_id;
    int schema_version;
    const char* frozen_schema_ddl;
    const char* fallback_kv_schema;
};

// Compile-time schema table for all 8 stores
inline constexpr SchemaDefinition kSchemaTable[] = {
    // StoreID::Node (0) - node.db
    {
        StoreID::Node,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS identity (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                secret_key BLOB NOT NULL,
                domain TEXT NOT NULL,
                created_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS routes (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                trust_score REAL NOT NULL,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_routes_node_id ON routes(node_id);
            CREATE INDEX IF NOT EXISTS idx_routes_last_seen ON routes(last_seen);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Mesh (1) - mesh.db
    {
        StoreID::Mesh,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS mesh_config (
                key BLOB PRIMARY KEY,
                mesh_id TEXT NOT NULL,
                genesis_suite_id INTEGER NOT NULL,
                authority_pubkey BLOB NOT NULL,
                epoch INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS members (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                role INTEGER NOT NULL,
                status INTEGER NOT NULL,
                joined_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_members_node_id ON members(node_id);
            CREATE INDEX IF NOT EXISTS idx_members_status ON members(status);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Session (2) - session.db
    {
        StoreID::Session,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS sessions (
                key BLOB PRIMARY KEY,
                session_id BLOB NOT NULL UNIQUE,
                requester TEXT NOT NULL,
                responder TEXT NOT NULL,
                capabilities INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                active INTEGER NOT NULL,
                tx_seq INTEGER NOT NULL DEFAULT 0,
                rx_seq INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_sessions_requester ON sessions(requester);
            CREATE INDEX IF NOT EXISTS idx_sessions_responder ON sessions(responder);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(active);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Trust (3) - trust.db
    {
        StoreID::Trust,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS trust_scores (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                citizen_score REAL NOT NULL,
                execution_score REAL NOT NULL,
                witness_score REAL NOT NULL,
                consistency_score REAL NOT NULL,
                composite_score REAL NOT NULL,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS attestations (
                key BLOB PRIMARY KEY,
                witness_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                claimed_score REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                signature BLOB NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_trust_node_id ON trust_scores(node_id);
            CREATE INDEX IF NOT EXISTS idx_attestations_subject ON attestations(subject_id);
            CREATE INDEX IF NOT EXISTS idx_attestations_witness ON attestations(witness_id);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Audit (4) - audit.db
    {
        StoreID::Audit,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS audit_log (
                key BLOB PRIMARY KEY,
                sequence INTEGER NOT NULL,
                contract_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                trigger TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                signature BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_audit_contract ON audit_log(contract_id);
            CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::DAG (5) - dag.db
    {
        StoreID::DAG,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS dags (
                key BLOB PRIMARY KEY,
                graph_id TEXT NOT NULL UNIQUE,
                intent_id TEXT NOT NULL,
                dag_json TEXT NOT NULL,
                dag_hash BLOB NOT NULL,
                compiled_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_dags_intent ON dags(intent_id);
            CREATE INDEX IF NOT EXISTS idx_dags_compiled ON dags(compiled_at);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Peer (6) - peer.db
    {
        StoreID::Peer,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS peers (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                rtt_ms REAL,
                health_score REAL NOT NULL DEFAULT 1.0,
                state INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS peer_events (
                key BLOB PRIMARY KEY,
                node_id TEXT NOT NULL,
                event_type INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                details TEXT
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_peers_node_id ON peers(node_id);
            CREATE INDEX IF NOT EXISTS idx_peers_state ON peers(state);
            CREATE INDEX IF NOT EXISTS idx_peer_events_node ON peer_events(node_id);
            CREATE INDEX IF NOT EXISTS idx_peer_events_time ON peer_events(timestamp);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Governance (7) - governance.db
    {
        StoreID::Governance,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS proposals (
                key BLOB PRIMARY KEY,
                proposal_id TEXT NOT NULL UNIQUE,
                proposer TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                proposal_type INTEGER NOT NULL,
                status INTEGER NOT NULL,
                votes_for INTEGER NOT NULL DEFAULT 0,
                votes_against INTEGER NOT NULL DEFAULT 0,
                votes_abstain INTEGER NOT NULL DEFAULT 0,
                quorum_required INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                executed_at INTEGER DEFAULT 0
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS votes (
                key BLOB PRIMARY KEY,
                proposal_id TEXT NOT NULL,
                voter_id TEXT NOT NULL,
                vote INTEGER NOT NULL,
                signature BLOB NOT NULL,
                timestamp INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);
            CREATE INDEX IF NOT EXISTS idx_proposals_expires ON proposals(expires_at);
            CREATE INDEX IF NOT EXISTS idx_votes_proposal ON votes(proposal_id);
            CREATE INDEX IF NOT EXISTS idx_votes_voter ON votes(voter_id);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },

    // StoreID::Policy (8) - policy.db
    {
        StoreID::Policy,
        1,
        R"(
            CREATE TABLE IF NOT EXISTS policies (
                key BLOB PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                version TEXT NOT NULL,
                yaml_content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS kv (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);
            CREATE INDEX IF NOT EXISTS idx_policies_updated ON policies(updated_at);
        )",
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"
    },
};

// Get schema definition for a store
inline const SchemaDefinition& get_schema(StoreID id)
{
    for (const auto& schema : kSchemaTable)
    {
        if (schema.store_id == id)
            return schema;
    }
    // Fallback - should never happen if all stores are defined
    static const SchemaDefinition fallback = {StoreID::Node, 1, "", "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;"};
    return fallback;
}

// Get the frozen DDL for a store
inline const char* get_frozen_schema(StoreID id)
{
    return get_schema(id).frozen_schema_ddl;
}

// Get the schema version for a store
inline int get_schema_version(StoreID id)
{
    return get_schema(id).schema_version;
}

} // namespace smo