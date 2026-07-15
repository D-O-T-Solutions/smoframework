#pragma once

#include <cstdint>
#include <system_error>

namespace smo {

enum class Errc : int32_t {
    // General
    OK                        = 0,
    UNKNOWN                   = 1,
    NOT_IMPLEMENTED           = 2,

    // Contract validation
    INVALID_CONTRACT          = 100,
    INVALID_SIGNATURE         = 101,
    INVALID_SESSION           = 102,
    INVALID_TIMESTAMP         = 103,

    // Policy / capability
    POLICY_DENIED             = 200,
    CAPABILITY_INSUFFICIENT   = 201,
    CAPABILITY_REVOKED        = 202,

    // Trust
    TRUST_INSUFFICIENT        = 300,
    WITNESS_UNAVAILABLE       = 301,
    WITNESS_REJECTED          = 302,

    // Execution
    EXECUTION_FAILED          = 400,
    EXECUTION_TIMEOUT         = 401,
    OPCODE_NOT_FOUND          = 402,
    OPCODE_NOT_IDEMPOTENT     = 403,

    // Transport
    CONNECTION_FAILED         = 500,
    SESSION_EXPIRED           = 501,
    REPLAY_DETECTED           = 502,

    // Storage
    STORE_UNAVAILABLE         = 600,
    STORE_CORRUPTION          = 601,
};

std::error_code make_error_code(Errc e) noexcept;

} // namespace smo

namespace std {
template <> struct is_error_code_enum<smo::Errc> : true_type {};
} // namespace std
