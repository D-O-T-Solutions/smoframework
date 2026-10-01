#include "wasm_host_functions.hpp"

#include <wasmtime.h>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <optional>

namespace smo::runtime::wasm {

// ── Thread-local memory storage (per-contract execution) ───────────────────
static thread_local wasmtime_memory_t* g_current_memory = nullptr;
static thread_local HostFunctionRegistry* g_current_registry = nullptr;

void set_current_wasm_memory(wasmtime_memory_t* memory) {
    g_current_memory = memory;
}

void set_current_host_registry(HostFunctionRegistry* registry) {
    g_current_registry = registry;
}

wasmtime_memory_t* get_current_wasm_memory() {
    return g_current_memory;
}

HostFunctionRegistry* get_current_host_registry() {
    return g_current_registry;
}

// ── Helper: WASM type creation ─────────────────────────────────────────────

static wasm_functype_t* make_func_type(const wasm_valkind_t* params, size_t nparams,
                                       const wasm_valkind_t* results, size_t nresults) {
    wasm_valtype_vec_t param_types;
    wasm_valtype_vec_t result_types;
    wasm_valtype_vec_new_uninitialized(&param_types, nparams);
    wasm_valtype_vec_new_uninitialized(&result_types, nresults);
    for (size_t i = 0; i < nparams; ++i) {
        param_types.data[i] = wasm_valtype_new(params[i]);
    }
    for (size_t i = 0; i < nresults; ++i) {
        result_types.data[i] = wasm_valtype_new(results[i]);
    }
    wasm_functype_t* func_type = wasm_functype_new(&param_types, &result_types);
    wasm_valtype_vec_delete(&param_types);
    wasm_valtype_vec_delete(&result_types);
    return func_type;
}

// Crypto function types
wasm_functype_t* make_crypto_sign_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 4, results, 2);
}

wasm_functype_t* make_crypto_verify_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32};
    return make_func_type(params, 6, results, 1);
}

wasm_functype_t* make_crypto_encrypt_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 4, results, 2);
}

wasm_functype_t* make_crypto_decrypt_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 4, results, 2);
}

wasm_functype_t* make_crypto_generate_key_type() {
    static const wasm_valkind_t params[] = {WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 1, results, 2);
}

// Vault function types
wasm_functype_t* make_vault_store_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

wasm_functype_t* make_vault_retrieve_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 2, results, 2);
}

wasm_functype_t* make_vault_delete_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

wasm_functype_t* make_vault_exists_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32};
    return make_func_type(params, 2, results, 1);
}

// Storage function types
wasm_functype_t* make_storage_put_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

wasm_functype_t* make_storage_get_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 2, results, 2);
}

wasm_functype_t* make_storage_erase_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

wasm_functype_t* make_storage_exists_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32};
    return make_func_type(params, 2, results, 1);
}

wasm_functype_t* make_storage_list_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 2, results, 2);
}

// Filesystem function types
wasm_functype_t* make_fs_read_text_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 2, results, 2);
}

wasm_functype_t* make_fs_read_binary_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 2, results, 2);
}

wasm_functype_t* make_fs_write_text_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

wasm_functype_t* make_fs_write_binary_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

wasm_functype_t* make_fs_exists_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32};
    return make_func_type(params, 2, results, 1);
}

// Network function types
wasm_functype_t* make_network_send_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

wasm_functype_t* make_network_request_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I64};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 5, results, 2);
}

// Transport function types
wasm_functype_t* make_transport_send_message_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 6, results, 0);
}

wasm_functype_t* make_transport_send_request_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I64};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 7, results, 2);
}

wasm_functype_t* make_transport_broadcast_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 4, results, 0);
}

// Scheduler function types
wasm_functype_t* make_scheduler_schedule_retry_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32, WASM_I64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 5, results, 0);
}

wasm_functype_t* make_scheduler_cancel_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

// Clock function types
wasm_functype_t* make_clock_now_ns_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I64};
    return make_func_type(params, 0, results, 1);
}

wasm_functype_t* make_clock_wall_clock_ns_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I64};
    return make_func_type(params, 0, results, 1);
}

wasm_functype_t* make_clock_advance_type() {
    static const wasm_valkind_t params[] = {WASM_I64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 1, results, 0);
}

// Random function types
wasm_functype_t* make_random_bytes_type() {
    static const wasm_valkind_t params[] = {WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 1, results, 2);
}

wasm_functype_t* make_random_u64_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I64};
    return make_func_type(params, 0, results, 1);
}

wasm_functype_t* make_random_seed_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

// Identity function types
wasm_functype_t* make_identity_node_id_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 0, results, 2);
}

wasm_functype_t* make_identity_mesh_id_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 0, results, 2);
}

wasm_functype_t* make_identity_public_key_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 0, results, 2);
}

wasm_functype_t* make_identity_fingerprint_type() {
    static const wasm_valkind_t params[] = {};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 0, results, 2);
}

// Audit function types
wasm_functype_t* make_audit_emit_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32,
                                            WASM_I32, WASM_I32, WASM_I32, WASM_I32,
                                            WASM_I64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 9, results, 0);
}

// Metrics function types
wasm_functype_t* make_metrics_increment_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 3, results, 0);
}

wasm_functype_t* make_metrics_gauge_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_F64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 3, results, 0);
}

wasm_functype_t* make_metrics_histogram_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_F64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 3, results, 0);
}

wasm_functype_t* make_metrics_timing_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I64};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 3, results, 0);
}

// Logger function types
wasm_functype_t* make_logger_debug_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

wasm_functype_t* make_logger_info_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

wasm_functype_t* make_logger_warn_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

wasm_functype_t* make_logger_error_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 2, results, 0);
}

// History function types
wasm_functype_t* make_history_record_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32, WASM_I32,
                                            WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {};
    return make_func_type(params, 7, results, 0);
}

wasm_functype_t* make_history_get_type() {
    static const wasm_valkind_t params[] = {WASM_I32, WASM_I32, WASM_I32};
    static const wasm_valkind_t results[] = {WASM_I32, WASM_I32};
    return make_func_type(params, 3, results, 2);
}

// ── Common helper to get registry, service, memory, context ────────────────

#define GET_SVC(svc_field) \
    auto* registry = static_cast<HostFunctionRegistry*>(env); \
    if (!registry) return nullptr; \
    auto* svc = registry->svc_field; \
    if (!svc) return nullptr; \
    auto* memory = g_current_memory; \
    if (!memory) return nullptr; \
    wasmtime_context_t* context = wasmtime_caller_context(caller); \
    (void)nargs; (void)nresults; (void)results;

#define GET_SVC_NO_RESULT(svc_field) \
    auto* registry = static_cast<HostFunctionRegistry*>(env); \
    if (!registry) return nullptr; \
    auto* svc = registry->svc_field; \
    if (!svc) return nullptr; \
    auto* memory = g_current_memory; \
    if (!memory) return nullptr; \
    wasmtime_context_t* context = wasmtime_caller_context(caller); \
    (void)nargs; (void)nresults;

// ── Crypto host functions ──────────────────────────────────────────────────

static wasm_trap_t* hf_crypto_sign(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC(crypto);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.crypto_sign);
    }
    uint32_t data_ptr = args[0].of.i32;
    uint32_t data_len = args[1].of.i32;
    uint32_t key_ptr = args[2].of.i32;
    uint32_t key_len = args[3].of.i32;

    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!data_result || !key_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto sig_result = svc->sign(data_result.value(), key_result.value());
    if (!sig_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, sig_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = sig_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_crypto_verify(void* env, wasmtime_caller_t* caller,
                                      const wasmtime_val_t* args, size_t nargs,
                                      wasmtime_val_t* results, size_t nresults) {
    GET_SVC(crypto);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.crypto_verify);
    }
    uint32_t data_ptr = args[0].of.i32;
    uint32_t data_len = args[1].of.i32;
    uint32_t sig_ptr = args[2].of.i32;
    uint32_t sig_len = args[3].of.i32;
    uint32_t pk_ptr = args[4].of.i32;
    uint32_t pk_len = args[5].of.i32;

    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    auto sig_result = read_wasm_bytes(context, memory, sig_ptr, sig_len);
    auto pk_result = read_wasm_bytes(context, memory, pk_ptr, pk_len);
    if (!data_result || !sig_result || !pk_result) { results[0].of.i32 = 0; return nullptr; }

    auto verify_result = svc->verify(data_result.value(), sig_result.value(), pk_result.value());
    results[0].of.i32 = (verify_result && verify_result.value()) ? 1 : 0;
    return nullptr;
}

static wasm_trap_t* hf_crypto_encrypt(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC(crypto);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.crypto_encrypt);
    }
    uint32_t pt_ptr = args[0].of.i32;
    uint32_t pt_len = args[1].of.i32;
    uint32_t pk_ptr = args[2].of.i32;
    uint32_t pk_len = args[3].of.i32;

    auto pt_result = read_wasm_bytes(context, memory, pt_ptr, pt_len);
    auto pk_result = read_wasm_bytes(context, memory, pk_ptr, pk_len);
    if (!pt_result || !pk_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto enc_result = svc->encrypt(pt_result.value(), pk_result.value());
    if (!enc_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, enc_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = enc_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_crypto_decrypt(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC(crypto);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.crypto_decrypt);
    }
    uint32_t ct_ptr = args[0].of.i32;
    uint32_t ct_len = args[1].of.i32;
    uint32_t key_ptr = args[2].of.i32;
    uint32_t key_len = args[3].of.i32;

    auto ct_result = read_wasm_bytes(context, memory, ct_ptr, ct_len);
    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!ct_result || !key_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto dec_result = svc->decrypt(ct_result.value(), key_result.value());
    if (!dec_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, dec_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = dec_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_crypto_generate_key(void* env, wasmtime_caller_t* caller,
                                            const wasmtime_val_t* args, size_t nargs,
                                            wasmtime_val_t* results, size_t nresults) {
    GET_SVC(crypto);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.crypto_gen_keypair);
    }
    int32_t key_type = args[0].of.i32;
    KeyType kt = static_cast<KeyType>(key_type);

    auto key_result = svc->generate_key(kt);
    if (!key_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_string(context, memory, key_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = key_result.value().size();
    return nullptr;
}

// ── Vault host functions ───────────────────────────────────────────────────

static wasm_trap_t* hf_vault_store(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(vault);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.vault_store);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;
    uint32_t secret_ptr = args[2].of.i32;
    uint32_t secret_len = args[3].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    auto secret_result = read_wasm_bytes(context, memory, secret_ptr, secret_len);
    if (!key_result || !secret_result) return nullptr;

    svc->store(key_result.value(), secret_result.value());
    return nullptr;
}

static wasm_trap_t* hf_vault_retrieve(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC(vault);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.vault_retrieve);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto retrieve_result = svc->retrieve(key_result.value());
    if (!retrieve_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, retrieve_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = retrieve_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_vault_delete(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(vault);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.vault_store); // Reuse vault_store cost
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) return nullptr;

    svc->delete_key(key_result.value());
    return nullptr;
}

static wasm_trap_t* hf_vault_exists(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC(vault);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.vault_retrieve); // Reuse vault_retrieve cost
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) { results[0].of.i32 = 0; return nullptr; }

    auto exists_result = svc->exists(key_result.value());
    results[0].of.i32 = (exists_result && exists_result.value()) ? 1 : 0;
    return nullptr;
}

// ── Storage host functions ─────────────────────────────────────────────────

static wasm_trap_t* hf_storage_put(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(storage);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.storage_put);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;
    uint32_t val_ptr = args[2].of.i32;
    uint32_t val_len = args[3].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    auto val_result = read_wasm_bytes(context, memory, val_ptr, val_len);
    if (!key_result || !val_result) return nullptr;

    svc->put(key_result.value(), val_result.value());
    return nullptr;
}

static wasm_trap_t* hf_storage_get(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC(storage);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.storage_get);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto get_result = svc->get(key_result.value());
    if (!get_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, get_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = get_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_storage_erase(void* env, wasmtime_caller_t* caller,
                                      const wasmtime_val_t* args, size_t nargs,
                                      wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(storage);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.storage_erase);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) return nullptr;

    svc->erase(key_result.value());
    return nullptr;
}

static wasm_trap_t* hf_storage_exists(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC(storage);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.storage_get);
    }
    uint32_t key_ptr = args[0].of.i32;
    uint32_t key_len = args[1].of.i32;

    auto key_result = read_wasm_string(context, memory, key_ptr, key_len);
    if (!key_result) { results[0].of.i32 = 0; return nullptr; }

    auto exists_result = svc->exists(key_result.value());
    results[0].of.i32 = (exists_result && exists_result.value()) ? 1 : 0;
    return nullptr;
}

static wasm_trap_t* hf_storage_list(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC(storage);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.storage_list);
    }
    uint32_t prefix_ptr = args[0].of.i32;
    uint32_t prefix_len = args[1].of.i32;

    auto prefix_result = read_wasm_string(context, memory, prefix_ptr, prefix_len);
    if (!prefix_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto list_result = svc->list(prefix_result.value());
    if (!list_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    std::string joined;
    for (const auto& key : list_result.value()) {
        joined += key;
        joined += '\0';
    }

    auto write_result = write_wasm_string(context, memory, joined);
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = list_result.value().size();
    return nullptr;
}

// ── Filesystem host functions ──────────────────────────────────────────────

static wasm_trap_t* hf_fs_read_text(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC(fs);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.fs_read);
    }
    uint32_t path_ptr = args[0].of.i32;
    uint32_t path_len = args[1].of.i32;

    auto path_result = read_wasm_string(context, memory, path_ptr, path_len);
    if (!path_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto read_result = svc->read_text(path_result.value());
    if (!read_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_string(context, memory, read_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = read_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_fs_read_binary(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC(fs);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.fs_read);
    }
    uint32_t path_ptr = args[0].of.i32;
    uint32_t path_len = args[1].of.i32;

    auto path_result = read_wasm_string(context, memory, path_ptr, path_len);
    if (!path_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto read_result = svc->read_binary(path_result.value());
    if (!read_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, read_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = read_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_fs_write_text(void* env, wasmtime_caller_t* caller,
                                      const wasmtime_val_t* args, size_t nargs,
                                      wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(fs);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.fs_write);
    }
    uint32_t path_ptr = args[0].of.i32;
    uint32_t path_len = args[1].of.i32;
    uint32_t content_ptr = args[2].of.i32;
    uint32_t content_len = args[3].of.i32;

    auto path_result = read_wasm_string(context, memory, path_ptr, path_len);
    auto content_result = read_wasm_string(context, memory, content_ptr, content_len);
    if (!path_result || !content_result) return nullptr;

    svc->write_text(path_result.value(), content_result.value());
    return nullptr;
}

static wasm_trap_t* hf_fs_write_binary(void* env, wasmtime_caller_t* caller,
                                        const wasmtime_val_t* args, size_t nargs,
                                        wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(fs);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.fs_write);
    }
    uint32_t path_ptr = args[0].of.i32;
    uint32_t path_len = args[1].of.i32;
    uint32_t data_ptr = args[2].of.i32;
    uint32_t data_len = args[3].of.i32;

    auto path_result = read_wasm_string(context, memory, path_ptr, path_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!path_result || !data_result) return nullptr;

    svc->write_binary(path_result.value(), data_result.value());
    return nullptr;
}

static wasm_trap_t* hf_fs_exists(void* env, wasmtime_caller_t* caller,
                                  const wasmtime_val_t* args, size_t nargs,
                                  wasmtime_val_t* results, size_t nresults) {
    GET_SVC(fs);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.fs_read);
    }
    uint32_t path_ptr = args[0].of.i32;
    uint32_t path_len = args[1].of.i32;

    auto path_result = read_wasm_string(context, memory, path_ptr, path_len);
    if (!path_result) { results[0].of.i32 = 0; return nullptr; }

    auto exists_result = svc->exists(path_result.value());
    results[0].of.i32 = (exists_result && exists_result.value()) ? 1 : 0;
    return nullptr;
}

// ── Network host functions ─────────────────────────────────────────────────

static wasm_trap_t* hf_network_send(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(network);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.network_send);
    }
    uint32_t target_ptr = args[0].of.i32;
    uint32_t target_len = args[1].of.i32;
    uint32_t data_ptr = args[2].of.i32;
    uint32_t data_len = args[3].of.i32;

    auto target_result = read_wasm_string(context, memory, target_ptr, target_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!target_result || !data_result) return nullptr;

    svc->send(target_result.value(), data_result.value());
    return nullptr;
}

static wasm_trap_t* hf_network_request(void* env, wasmtime_caller_t* caller,
                                        const wasmtime_val_t* args, size_t nargs,
                                        wasmtime_val_t* results, size_t nresults) {
    GET_SVC(network);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.network_recv);
    }
    uint32_t target_ptr = args[0].of.i32;
    uint32_t target_len = args[1].of.i32;
    uint32_t data_ptr = args[2].of.i32;
    uint32_t data_len = args[3].of.i32;
    uint64_t timeout_ns = args[4].of.i64;

    auto target_result = read_wasm_string(context, memory, target_ptr, target_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!target_result || !data_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto req_result = svc->request(target_result.value(), data_result.value(), timeout_ns);
    if (!req_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, req_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = req_result.value().size();
    return nullptr;
}

// ── Transport host functions ───────────────────────────────────────────────

static wasm_trap_t* hf_transport_send_message(void* env, wasmtime_caller_t* caller,
                                               const wasmtime_val_t* args, size_t nargs,
                                               wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(transport);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.network_send);
    }
    uint32_t target_ptr = args[0].of.i32;
    uint32_t target_len = args[1].of.i32;
    uint32_t opcode_ptr = args[2].of.i32;
    uint32_t opcode_len = args[3].of.i32;
    uint32_t data_ptr = args[4].of.i32;
    uint32_t data_len = args[5].of.i32;

    auto target_result = read_wasm_string(context, memory, target_ptr, target_len);
    auto opcode_result = read_wasm_string(context, memory, opcode_ptr, opcode_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!target_result || !opcode_result || !data_result) return nullptr;

    svc->send_message(target_result.value(), opcode_result.value(), data_result.value());
    return nullptr;
}

static wasm_trap_t* hf_transport_send_request(void* env, wasmtime_caller_t* caller,
                                               const wasmtime_val_t* args, size_t nargs,
                                               wasmtime_val_t* results, size_t nresults) {
    GET_SVC(transport);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.network_recv);
    }
    uint32_t target_ptr = args[0].of.i32;
    uint32_t target_len = args[1].of.i32;
    uint32_t opcode_ptr = args[2].of.i32;
    uint32_t opcode_len = args[3].of.i32;
    uint32_t data_ptr = args[4].of.i32;
    uint32_t data_len = args[5].of.i32;
    uint64_t timeout_ns = args[6].of.i64;

    auto target_result = read_wasm_string(context, memory, target_ptr, target_len);
    auto opcode_result = read_wasm_string(context, memory, opcode_ptr, opcode_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!target_result || !opcode_result || !data_result) {
        results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr;
    }

    auto req_result = svc->send_request(target_result.value(), opcode_result.value(),
                                        data_result.value(), timeout_ns);
    if (!req_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, req_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = req_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_transport_broadcast(void* env, wasmtime_caller_t* caller,
                                            const wasmtime_val_t* args, size_t nargs,
                                            wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(transport);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.network_send);
    }
    uint32_t opcode_ptr = args[0].of.i32;
    uint32_t opcode_len = args[1].of.i32;
    uint32_t data_ptr = args[2].of.i32;
    uint32_t data_len = args[3].of.i32;

    auto opcode_result = read_wasm_string(context, memory, opcode_ptr, opcode_len);
    auto data_result = read_wasm_bytes(context, memory, data_ptr, data_len);
    if (!opcode_result || !data_result) return nullptr;

    svc->broadcast(opcode_result.value(), data_result.value());
    return nullptr;
}

// ── Scheduler host functions ───────────────────────────────────────────────

static wasm_trap_t* hf_scheduler_schedule_retry(void* env, wasmtime_caller_t* caller,
                                                 const wasmtime_val_t* args, size_t nargs,
                                                 wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(scheduler);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_increment); // Reuse a similar cost
    }
    uint32_t exec_id_ptr = args[0].of.i32;
    uint32_t exec_id_len = args[1].of.i32;
    uint32_t step_id_ptr = args[2].of.i32;
    uint32_t step_id_len = args[3].of.i32;
    uint64_t delay_ns = args[4].of.i64;

    auto exec_id_result = read_wasm_string(context, memory, exec_id_ptr, exec_id_len);
    auto step_id_result = read_wasm_string(context, memory, step_id_ptr, step_id_len);
    if (!exec_id_result || !step_id_result) return nullptr;

    svc->schedule_retry(exec_id_result.value(), step_id_result.value(), delay_ns);
    return nullptr;
}

static wasm_trap_t* hf_scheduler_cancel(void* env, wasmtime_caller_t* caller,
                                         const wasmtime_val_t* args, size_t nargs,
                                         wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(scheduler);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_increment); // Reuse a similar cost
    }
    uint32_t exec_id_ptr = args[0].of.i32;
    uint32_t exec_id_len = args[1].of.i32;

    auto exec_id_result = read_wasm_string(context, memory, exec_id_ptr, exec_id_len);
    if (!exec_id_result) return nullptr;

    svc->cancel_scheduled(exec_id_result.value());
    return nullptr;
}

// ── Clock host functions ───────────────────────────────────────────────────

static wasm_trap_t* hf_clock_now_ns(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    (void)caller; (void)args; (void)nargs; (void)nresults;
    auto* registry = static_cast<HostFunctionRegistry*>(env);
    if (!registry || !registry->clock) { results[0].of.i64 = 0; return nullptr; }
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.clock_now);
    }
    results[0].of.i64 = registry->clock->now_ns();
    return nullptr;
}

static wasm_trap_t* hf_clock_wall_clock_ns(void* env, wasmtime_caller_t* caller,
                                           const wasmtime_val_t* args, size_t nargs,
                                           wasmtime_val_t* results, size_t nresults) {
    (void)caller; (void)args; (void)nargs; (void)nresults;
    auto* registry = static_cast<HostFunctionRegistry*>(env);
    if (!registry || !registry->clock) { results[0].of.i64 = 0; return nullptr; }
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.clock_now);
    }
    results[0].of.i64 = registry->clock->wall_clock_ns();
    return nullptr;
}

static wasm_trap_t* hf_clock_advance(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    (void)caller; (void)nargs; (void)nresults; (void)results;
    auto* registry = static_cast<HostFunctionRegistry*>(env);
    if (!registry || !registry->clock) return nullptr;
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.clock_now);
    }
    uint64_t delta_ns = args[0].of.i64;
    registry->clock->advance(delta_ns);
    return nullptr;
}

// ── Random host functions ──────────────────────────────────────────────────

static wasm_trap_t* hf_random_bytes(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC(random);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.random_bytes);
    }
    uint32_t count = args[0].of.i32;
    Bytes bytes = svc->random_bytes(count);

    auto write_result = write_wasm_bytes(context, memory, bytes);
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = bytes.size();
    return nullptr;
}

static wasm_trap_t* hf_random_u64(void* env, wasmtime_caller_t* caller,
                                  const wasmtime_val_t* args, size_t nargs,
                                  wasmtime_val_t* results, size_t nresults) {
    (void)caller; (void)args; (void)nargs; (void)nresults;
    auto* registry = static_cast<HostFunctionRegistry*>(env);
    if (!registry || !registry->random) { results[0].of.i64 = 0; return nullptr; }
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.random_u64);
    }
    results[0].of.i64 = registry->random->random_u64();
    return nullptr;
}

static wasm_trap_t* hf_random_seed(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(random);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.random_bytes);
    }
    uint32_t entropy_ptr = args[0].of.i32;
    uint32_t entropy_len = args[1].of.i32;

    auto entropy_result = read_wasm_bytes(context, memory, entropy_ptr, entropy_len);
    if (!entropy_result) return nullptr;

    svc->seed(entropy_result.value());
    return nullptr;
}

// ── Identity host functions ────────────────────────────────────────────────

static wasm_trap_t* hf_identity_node_id(void* env, wasmtime_caller_t* caller,
                                        const wasmtime_val_t* args, size_t nargs,
                                        wasmtime_val_t* results, size_t nresults) {
    GET_SVC(identity);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.identity_node_id);
    }
    auto id_result = svc->node_id();
    if (!id_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_string(context, memory, id_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = id_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_identity_mesh_id(void* env, wasmtime_caller_t* caller,
                                        const wasmtime_val_t* args, size_t nargs,
                                        wasmtime_val_t* results, size_t nresults) {
    GET_SVC(identity);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.identity_mesh_id);
    }
    auto id_result = svc->mesh_id();
    if (!id_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_string(context, memory, id_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = id_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_identity_public_key(void* env, wasmtime_caller_t* caller,
                                           const wasmtime_val_t* args, size_t nargs,
                                           wasmtime_val_t* results, size_t nresults) {
    GET_SVC(identity);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.identity_public_key);
    }
    auto pk_result = svc->public_key();
    if (!pk_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_bytes(context, memory, pk_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = pk_result.value().size();
    return nullptr;
}

static wasm_trap_t* hf_identity_fingerprint(void* env, wasmtime_caller_t* caller,
                                            const wasmtime_val_t* args, size_t nargs,
                                            wasmtime_val_t* results, size_t nresults) {
    GET_SVC(identity);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.identity_fingerprint);
    }
    auto fp_result = svc->fingerprint();
    if (!fp_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto write_result = write_wasm_string(context, memory, fp_result.value());
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = fp_result.value().size();
    return nullptr;
}

// ── Audit host functions ───────────────────────────────────────────────────

static wasm_trap_t* hf_audit_emit(void* env, wasmtime_caller_t* caller,
                                   const wasmtime_val_t* args, size_t nargs,
                                   wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(audit);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.audit_emit);
    }
    uint32_t event_type_ptr = args[0].of.i32;
    uint32_t event_type_len = args[1].of.i32;
    uint32_t source_id_ptr = args[2].of.i32;
    uint32_t source_id_len = args[3].of.i32;
    uint32_t correlation_id_ptr = args[4].of.i32;
    uint32_t correlation_id_len = args[5].of.i32;
    uint32_t details_ptr = args[6].of.i32;
    uint32_t details_len = args[7].of.i32;
    uint64_t timestamp_ns = args[8].of.i64;

    auto event_type_result = read_wasm_string(context, memory, event_type_ptr, event_type_len);
    auto source_id_result = read_wasm_string(context, memory, source_id_ptr, source_id_len);
    auto correlation_id_result = read_wasm_string(context, memory, correlation_id_ptr, correlation_id_len);
    auto details_result = read_wasm_string(context, memory, details_ptr, details_len);
    if (!event_type_result || !source_id_result || !correlation_id_result || !details_result) return nullptr;

    AuditEvent event;
    event.event_type = event_type_result.value();
    event.source_id = source_id_result.value();
    event.correlation_id = correlation_id_result.value();
    event.details = details_result.value();
    event.timestamp_ns = timestamp_ns;

    svc->emit(event);
    return nullptr;
}

// ── Metrics host functions ─────────────────────────────────────────────────

static wasm_trap_t* hf_metrics_increment(void* env, wasmtime_caller_t* caller,
                                          const wasmtime_val_t* args, size_t nargs,
                                          wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(metrics);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_increment);
    }
    uint32_t metric_ptr = args[0].of.i32;
    uint32_t metric_len = args[1].of.i32;
    int64_t delta = args[2].of.i64;

    auto metric_result = read_wasm_string(context, memory, metric_ptr, metric_len);
    if (!metric_result) return nullptr;

    svc->increment(metric_result.value(), delta);
    return nullptr;
}

static wasm_trap_t* hf_metrics_gauge(void* env, wasmtime_caller_t* caller,
                                      const wasmtime_val_t* args, size_t nargs,
                                      wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(metrics);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_gauge);
    }
    uint32_t metric_ptr = args[0].of.i32;
    uint32_t metric_len = args[1].of.i32;
    double value = args[2].of.f64;

    auto metric_result = read_wasm_string(context, memory, metric_ptr, metric_len);
    if (!metric_result) return nullptr;

    svc->gauge(metric_result.value(), value);
    return nullptr;
}

static wasm_trap_t* hf_metrics_histogram(void* env, wasmtime_caller_t* caller,
                                          const wasmtime_val_t* args, size_t nargs,
                                          wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(metrics);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_histogram);
    }
    uint32_t metric_ptr = args[0].of.i32;
    uint32_t metric_len = args[1].of.i32;
    double value = args[2].of.f64;

    auto metric_result = read_wasm_string(context, memory, metric_ptr, metric_len);
    if (!metric_result) return nullptr;

    svc->histogram(metric_result.value(), value);
    return nullptr;
}

static wasm_trap_t* hf_metrics_timing(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(metrics);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.metrics_timing);
    }
    uint32_t metric_ptr = args[0].of.i32;
    uint32_t metric_len = args[1].of.i32;
    uint64_t duration_ns = args[2].of.i64;

    auto metric_result = read_wasm_string(context, memory, metric_ptr, metric_len);
    if (!metric_result) return nullptr;

    svc->timing(metric_result.value(), duration_ns);
    return nullptr;
}

// ── Logger host functions ──────────────────────────────────────────────────

static wasm_trap_t* hf_logger_debug(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(logger);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.logger_debug);
    }
    uint32_t msg_ptr = args[0].of.i32;
    uint32_t msg_len = args[1].of.i32;

    auto msg_result = read_wasm_string(context, memory, msg_ptr, msg_len);
    if (!msg_result) return nullptr;

    svc->debug(msg_result.value());
    return nullptr;
}

static wasm_trap_t* hf_logger_info(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(logger);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.logger_info);
    }
    uint32_t msg_ptr = args[0].of.i32;
    uint32_t msg_len = args[1].of.i32;

    auto msg_result = read_wasm_string(context, memory, msg_ptr, msg_len);
    if (!msg_result) return nullptr;

    svc->info(msg_result.value());
    return nullptr;
}

static wasm_trap_t* hf_logger_warn(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(logger);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.logger_warn);
    }
    uint32_t msg_ptr = args[0].of.i32;
    uint32_t msg_len = args[1].of.i32;

    auto msg_result = read_wasm_string(context, memory, msg_ptr, msg_len);
    if (!msg_result) return nullptr;

    svc->warn(msg_result.value());
    return nullptr;
}

static wasm_trap_t* hf_logger_error(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(logger);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.logger_error);
    }
    uint32_t msg_ptr = args[0].of.i32;
    uint32_t msg_len = args[1].of.i32;

    auto msg_result = read_wasm_string(context, memory, msg_ptr, msg_len);
    if (!msg_result) return nullptr;

    svc->error(msg_result.value());
    return nullptr;
}

// ── History host functions ─────────────────────────────────────────────────

static wasm_trap_t* hf_history_record(void* env, wasmtime_caller_t* caller,
                                       const wasmtime_val_t* args, size_t nargs,
                                       wasmtime_val_t* results, size_t nresults) {
    GET_SVC_NO_RESULT(history);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.history_record);
    }
    uint32_t exec_id_ptr = args[0].of.i32;
    uint32_t exec_id_len = args[1].of.i32;
    uint32_t contract_id_ptr = args[2].of.i32;
    uint32_t contract_id_len = args[3].of.i32;
    int32_t success = args[4].of.i32;
    uint32_t details_ptr = args[5].of.i32;
    uint32_t details_len = args[6].of.i32;

    auto exec_id_result = read_wasm_string(context, memory, exec_id_ptr, exec_id_len);
    auto contract_id_result = read_wasm_string(context, memory, contract_id_ptr, contract_id_len);
    auto details_result = read_wasm_string(context, memory, details_ptr, details_len);
    if (!exec_id_result || !contract_id_result || !details_result) return nullptr;

    svc->record_execution(exec_id_result.value(), contract_id_result.value(),
                          success != 0, details_result.value());
    return nullptr;
}

static wasm_trap_t* hf_history_get(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
    GET_SVC(history);
    if (registry->engine) {
        registry->engine->consume_fuel(registry->engine->config().host_costs.history_get);
    }
    uint32_t contract_id_ptr = args[0].of.i32;
    uint32_t contract_id_len = args[1].of.i32;
    uint32_t limit = args[2].of.i32;

    auto contract_id_result = read_wasm_string(context, memory, contract_id_ptr, contract_id_len);
    if (!contract_id_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    auto history_result = svc->get_history(contract_id_result.value(), limit);
    if (!history_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    std::string joined;
    for (const auto& entry : history_result.value()) {
        joined += entry;
        joined += '\0';
    }

    auto write_result = write_wasm_string(context, memory, joined);
    if (!write_result) { results[0].of.i32 = 0; results[1].of.i32 = 0; return nullptr; }

    results[0].of.i32 = write_result.value();
    results[1].of.i32 = history_result.value().size();
    return nullptr;
}

// ── Memory access helpers ──────────────────────────────────────────────────

Result<std::string> read_wasm_string(wasmtime_context_t* context, wasmtime_memory_t* memory,
                                     uint32_t ptr, uint32_t len) {
    if (!memory || len == 0) return std::string();
    uint8_t* data = wasmtime_memory_data(context, memory);
    size_t data_size = wasmtime_memory_data_size(context, memory);
    if (ptr + len > data_size) {
        return SMO_ERR_RUNTIME(300, Error, NoRetry, None, "WASM memory read out of bounds");
    }
    return std::string(reinterpret_cast<char*>(data + ptr), len);
}

Result<Bytes> read_wasm_bytes(wasmtime_context_t* context, wasmtime_memory_t* memory,
                              uint32_t ptr, uint32_t len) {
    if (!memory || len == 0) return Bytes();
    uint8_t* data = wasmtime_memory_data(context, memory);
    size_t data_size = wasmtime_memory_data_size(context, memory);
    if (ptr + len > data_size) {
        return SMO_ERR_RUNTIME(301, Error, NoRetry, None, "WASM memory read out of bounds");
    }
    Bytes result(len);
    std::memcpy(result.data(), data + ptr, len);
    return result;
}

Result<uint32_t> write_wasm_string(wasmtime_context_t* context, wasmtime_memory_t* memory,
                                   const std::string& str) {
    return write_wasm_bytes(context, memory, Bytes(str.begin(), str.end()));
}

Result<uint32_t> write_wasm_bytes(wasmtime_context_t* context, wasmtime_memory_t* memory,
                                  const Bytes& bytes) {
    if (!memory) return SMO_ERR_RUNTIME(302, Error, NoRetry, None, "No WASM memory");
    static thread_local uint32_t bump_ptr = 1024 * 1024;
    uint32_t ptr = bump_ptr;
    bump_ptr += (bytes.size() + 7) & ~7;

    uint8_t* data = wasmtime_memory_data(context, memory);
    size_t data_size = wasmtime_memory_data_size(context, memory);
    if (bump_ptr > data_size) {
        return SMO_ERR_RUNTIME(303, Error, NoRetry, None, "WASM memory exhausted");
    }
    std::memcpy(data + ptr, bytes.data(), bytes.size());
    return ptr;
}

Result<wasmtime_memory_t> get_instance_memory(wasmtime_context_t* context, wasmtime_instance_t* instance) {
    wasmtime_extern_t extern_val;
    bool ok = wasmtime_instance_export_get(context, instance, "memory", 6, &extern_val);
    if (!ok || extern_val.kind != WASMTIME_EXTERN_MEMORY) {
        return SMO_ERR_RUNTIME(304, Error, NoRetry, None, "Memory export not found");
    }
    wasmtime_memory_t memory = extern_val.of.memory;
    wasmtime_extern_delete(&extern_val);
    return memory;
}

// ── HostFunctionRegistry::register_all ────────────────────────────────────

void HostFunctionRegistry::register_all(wasmtime_linker_t* linker) {
    // Solution 1 (Local Memory Definition & Export - Industry Standard):
    // Contracts now DEFINE their own memory locally and EXPORT it.
    // Host does NOT import memory into the linker.
    // After instantiation, host gets the exported memory via wasmtime_instance_export_get("memory").
    // This avoids Wasmtime v35 linker segfault with memory imports.
    // Used by Polkadot Substrate, CosmWasm, and other major WASM blockchain ecosystems.

    auto define = [&](const char* name, wasm_functype_t* type, wasmtime_func_callback_t callback) {
        wasmtime_linker_define_func(linker, SMO_HOST_NAMESPACE, strlen(SMO_HOST_NAMESPACE),
                                    name, strlen(name), type, callback, this, nullptr);
    };

    // Crypto (capability: Crypto)
    if (has_capability(ContractCapability::Crypto) && crypto) {
        define(HF_CRYPTO_SIGN, make_crypto_sign_type(), hf_crypto_sign);
        define(HF_CRYPTO_VERIFY, make_crypto_verify_type(), hf_crypto_verify);
        define(HF_CRYPTO_ENCRYPT, make_crypto_encrypt_type(), hf_crypto_encrypt);
        define(HF_CRYPTO_DECRYPT, make_crypto_decrypt_type(), hf_crypto_decrypt);
        define(HF_CRYPTO_GENERATE_KEY, make_crypto_generate_key_type(), hf_crypto_generate_key);
    }

    // Vault (capability: Vault)
    if (has_capability(ContractCapability::Vault) && vault) {
        define(HF_VAULT_STORE, make_vault_store_type(), hf_vault_store);
        define(HF_VAULT_RETRIEVE, make_vault_retrieve_type(), hf_vault_retrieve);
        define(HF_VAULT_DELETE, make_vault_delete_type(), hf_vault_delete);
        define(HF_VAULT_EXISTS, make_vault_exists_type(), hf_vault_exists);
    }

    // Storage (capability: Storage)
    if (has_capability(ContractCapability::Storage) && storage) {
        define(HF_STORAGE_PUT, make_storage_put_type(), hf_storage_put);
        define(HF_STORAGE_GET, make_storage_get_type(), hf_storage_get);
        define(HF_STORAGE_ERASE, make_storage_erase_type(), hf_storage_erase);
        define(HF_STORAGE_EXISTS, make_storage_exists_type(), hf_storage_exists);
        define(HF_STORAGE_LIST, make_storage_list_type(), hf_storage_list);
    }

    // Filesystem (capability: Filesystem)
    if (has_capability(ContractCapability::Filesystem) && fs) {
        define(HF_FS_READ_TEXT, make_fs_read_text_type(), hf_fs_read_text);
        define(HF_FS_READ_BINARY, make_fs_read_binary_type(), hf_fs_read_binary);
        define(HF_FS_WRITE_TEXT, make_fs_write_text_type(), hf_fs_write_text);
        define(HF_FS_WRITE_BINARY, make_fs_write_binary_type(), hf_fs_write_binary);
        define(HF_FS_EXISTS, make_fs_exists_type(), hf_fs_exists);
    }

    // Network (capability: Network)
    if (has_capability(ContractCapability::Network) && network) {
        define(HF_NETWORK_SEND, make_network_send_type(), hf_network_send);
        define(HF_NETWORK_REQUEST, make_network_request_type(), hf_network_request);
    }

    // Transport (capability: Network)
    if (has_capability(ContractCapability::Network) && transport) {
        define(HF_TRANSPORT_SEND_MESSAGE, make_transport_send_message_type(), hf_transport_send_message);
        define(HF_TRANSPORT_SEND_REQUEST, make_transport_send_request_type(), hf_transport_send_request);
        define(HF_TRANSPORT_BROADCAST, make_transport_broadcast_type(), hf_transport_broadcast);
    }

    // Scheduler (capability: Scheduler)
    if (has_capability(ContractCapability::Scheduler) && scheduler) {
        define(HF_SCHEDULER_SCHEDULE_RETRY, make_scheduler_schedule_retry_type(), hf_scheduler_schedule_retry);
        define(HF_SCHEDULER_CANCEL, make_scheduler_cancel_type(), hf_scheduler_cancel);
    }

    // Clock (always available)
    if (clock) {
        define(HF_CLOCK_NOW_NS, make_clock_now_ns_type(), hf_clock_now_ns);
        define(HF_CLOCK_WALL_CLOCK_NS, make_clock_wall_clock_ns_type(), hf_clock_wall_clock_ns);
        define(HF_CLOCK_ADVANCE, make_clock_advance_type(), hf_clock_advance);
    }

    // Random (always available)
    if (random) {
        define(HF_RANDOM_BYTES, make_random_bytes_type(), hf_random_bytes);
        define(HF_RANDOM_U64, make_random_u64_type(), hf_random_u64);
        define(HF_RANDOM_SEED, make_random_seed_type(), hf_random_seed);
    }

    // Identity (capability: Identity)
    if (has_capability(ContractCapability::Identity) && identity) {
        define(HF_IDENTITY_NODE_ID, make_identity_node_id_type(), hf_identity_node_id);
        define(HF_IDENTITY_MESH_ID, make_identity_mesh_id_type(), hf_identity_mesh_id);
        define(HF_IDENTITY_PUBLIC_KEY, make_identity_public_key_type(), hf_identity_public_key);
        define(HF_IDENTITY_FINGERPRINT, make_identity_fingerprint_type(), hf_identity_fingerprint);
    }

    // Audit (capability: Audit)
    if (has_capability(ContractCapability::Audit) && audit) {
        define(HF_AUDIT_EMIT, make_audit_emit_type(), hf_audit_emit);
    }

    // Metrics (capability: Metrics)
    if (has_capability(ContractCapability::Metrics) && metrics) {
        define(HF_METRICS_INCREMENT, make_metrics_increment_type(), hf_metrics_increment);
        define(HF_METRICS_GAUGE, make_metrics_gauge_type(), hf_metrics_gauge);
        define(HF_METRICS_HISTOGRAM, make_metrics_histogram_type(), hf_metrics_histogram);
        define(HF_METRICS_TIMING, make_metrics_timing_type(), hf_metrics_timing);
    }

    // Logger (always available)
    if (logger) {
        define(HF_LOGGER_DEBUG, make_logger_debug_type(), hf_logger_debug);
        define(HF_LOGGER_INFO, make_logger_info_type(), hf_logger_info);
        define(HF_LOGGER_WARN, make_logger_warn_type(), hf_logger_warn);
        define(HF_LOGGER_ERROR, make_logger_error_type(), hf_logger_error);
    }

    // History (always available)
    if (history) {
        define(HF_HISTORY_RECORD, make_history_record_type(), hf_history_record);
        define(HF_HISTORY_GET, make_history_get_type(), hf_history_get);
    }
}

} // namespace smo::runtime::wasm