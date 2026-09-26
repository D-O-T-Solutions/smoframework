#pragma once

#include <cstdint>
#include <string_view>

namespace smo {

    enum class Opcode : uint8_t
    {
        // MVP (§XVIII.1)
        LS = 0x01,
        PUT = 0x02,
        GET = 0x03,
        EXEC = 0x04,
        QUARANTINE = 0x05,

        // Post-MVP (§XVIII.2)
        MKDIR = 0x10,
        RM = 0x11,
        CP = 0x12,

        // Governance & Recovery
        REVOKE_CERT = 0x20,
        EPOCH_INCREMENT = 0x21,
        RECOVERY_SESSION = 0x22,
        CRL_SYNC = 0x23,

        // Governance Contract (Sprint 36D.3)
        GOV_PROPOSE = 0x24,
        GOV_VOTE = 0x25,
        GOV_COMMIT = 0x26,

        // Echo (Sprint 37 E2E test)
        ECHO = 0x06,

        // Session lifecycle (CONTROL namespace 0x02, message_id 0x0010/0x0011/0x0012 per RFC 0020)
        // Internal values 0x40-0x42 to avoid conflict with MKDIR/RM/CP (0x10-0x12)
        SESSION_OPEN = 0x40,
        SESSION_CLOSE = 0x41,
        SESSION_RENEW = 0x42,

        // Bootstrap Contract methods
        BOOTSTRAP_SNAPSHOT = 0x30,
        BOOTSTRAP_INFO = 0x31,

        // Join Contract methods
        JOIN = 0x33,
        LEAVE = 0x34,
        JOIN_INFO = 0x35,

        // Governance additional methods
        GOV_LIST = 0x27,
        GOV_STATUS = 0x28,
        GOV_INFO = 0x29,

        // Recovery (single opcode, method in payload)
        RECOVERY = 0x2A,

        // File (single opcode, method in payload)
        FILE_OP = 0x2B,

        // Process (single opcode, method in payload)
        PROCESS = 0x2C,

        // Contract lifecycle management (single opcode, method in payload)
        CONTRACT_MGMT = 0x2D,

        // Witness/trust (single opcode, method in payload — RFC 0003 §3, RFC 0017)
        WITNESS = 0x2E,

        // Channel Model (RFC 0042) — Data namespace 0x04
        CHANNEL_OPEN = 0x60,
        CHANNEL_CHUNK = 0x61,
        CHANNEL_ACK = 0x62,
        CHANNEL_NACK = 0x63,
        CHANNEL_FIN = 0x64,
        CHANNEL_CANCEL = 0x65,
        CHANNEL_WINDOW_UPDATE = 0x66,

        CUSTOM = 0xFF,
    };

    struct OpcodeInfo
    {
        Opcode code;
        std::string_view name;
        bool idempotent;
        uint32_t required_capability_mask;
    };

    constexpr OpcodeInfo opcode_info(Opcode code) noexcept
    {
        switch (code)
        {
            case Opcode::LS:              return {code, "ls",              true,  0x01};
            case Opcode::PUT:             return {code, "put",             true,  0x01};
            case Opcode::GET:             return {code, "get",             true,  0x01};
            case Opcode::EXEC:            return {code, "exec",            false, 0x01};
            case Opcode::QUARANTINE:      return {code, "quarantine",      false, 0x01};
            case Opcode::MKDIR:           return {code, "mkdir",           true,  0x01};
            case Opcode::RM:              return {code, "rm",              false, 0x01};
            case Opcode::CP:              return {code, "cp",              true,  0x01};
            case Opcode::REVOKE_CERT:     return {code, "revoke_cert",     false, 0x01};
            case Opcode::EPOCH_INCREMENT: return {code, "epoch_increment", false, 0x01};
            case Opcode::RECOVERY_SESSION:return {code, "recovery_session",false, 0x01};
            case Opcode::CRL_SYNC:        return {code, "crl_sync",        true,  0x01};
            case Opcode::GOV_PROPOSE:     return {code, "gov_propose",     false, 0x01};
            case Opcode::GOV_VOTE:        return {code, "gov_vote",        false, 0x01};
            case Opcode::GOV_COMMIT:      return {code, "gov_commit",      true,  0x01};
            case Opcode::ECHO:            return {code, "echo",            true,  0x01};
            case Opcode::SESSION_OPEN:    return {code, "session_open",    false, 0x01};
            case Opcode::SESSION_CLOSE:   return {code, "session_close",   true,  0x01};
            case Opcode::SESSION_RENEW:   return {code, "session_renew",   false, 0x01};
            case Opcode::BOOTSTRAP_SNAPSHOT: return {code, "bootstrap_snapshot", true, 0x01};
            case Opcode::BOOTSTRAP_INFO:  return {code, "bootstrap_info",  true,  0x01};
            case Opcode::JOIN:            return {code, "join",            false, 0x01};
            case Opcode::LEAVE:           return {code, "leave",           true,  0x01};
            case Opcode::JOIN_INFO:       return {code, "join_info",       true,  0x01};
            case Opcode::GOV_LIST:        return {code, "gov_list",        true,  0x01};
            case Opcode::GOV_STATUS:      return {code, "gov_status",      true,  0x01};
            case Opcode::GOV_INFO:        return {code, "gov_info",        true,  0x01};
            case Opcode::RECOVERY:        return {code, "recovery",        false, 0x01};
            case Opcode::FILE_OP:         return {code, "file_op",         false, 0x01};
            case Opcode::PROCESS:         return {code, "process",         false, 0x01};
            case Opcode::CONTRACT_MGMT:   return {code, "contract_mgmt",   false, 0x01};
            case Opcode::WITNESS:         return {code, "witness",         false, 0x01};
            case Opcode::CHANNEL_OPEN:    return {code, "channel_open",    false, 0x01};
            case Opcode::CHANNEL_CHUNK:   return {code, "channel_chunk",   false, 0x01};
            case Opcode::CHANNEL_ACK:     return {code, "channel_ack",     true,  0x01};
            case Opcode::CHANNEL_NACK:    return {code, "channel_nack",    false, 0x01};
            case Opcode::CHANNEL_FIN:     return {code, "channel_fin",     true,  0x01};
            case Opcode::CHANNEL_CANCEL:  return {code, "channel_cancel",  false, 0x01};
            case Opcode::CHANNEL_WINDOW_UPDATE: return {code, "channel_window_update", true, 0x01};
            case Opcode::CUSTOM:          return {code, "custom",          false, 0x01};
            default:                      return {code, "unknown",         false, 0};
        }
    }

} // namespace smo
