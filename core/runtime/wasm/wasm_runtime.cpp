#include "wasm_runtime.hpp"
#include "wasm_host_function_names.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace smo::runtime::wasm {

namespace {

void check_wasm_error(const char* msg, const char* file, int line) {
    std::fprintf(stderr, "[wasm] ERROR at %s:%d: %s\n", file, line, msg);
    std::abort();
}

#define CHECK_WASM(cond, msg) do { if (!(cond)) check_wasm_error(msg, __FILE__, __LINE__); } while(0)

// Convert wasmtime_val_t to wasm_val_t
static void wasmtime_to_wasm_val(const wasmtime_val_t& src, wasm_val_t& dst) {
    dst.kind = static_cast<wasm_valkind_t>(src.kind);
    switch (src.kind) {
        case WASMTIME_I32:
            dst.of.i32 = src.of.i32;
            break;
        case WASMTIME_I64:
            dst.of.i64 = src.of.i64;
            break;
        case WASMTIME_F32:
            dst.of.f32 = src.of.f32;
            break;
        case WASMTIME_F64:
            dst.of.f64 = src.of.f64;
            break;
        case WASMTIME_FUNCREF:
            dst.of.ref = reinterpret_cast<wasm_ref_t*>(src.of.funcref.__private);
            break;
        default:
            std::memset(&dst.of, 0, sizeof(dst.of));
            break;
    }
}

// Convert wasm_val_t to wasmtime_val_t
static void wasm_to_wasmtime_val(const wasm_val_t& src, wasmtime_val_t& dst) {
    dst.kind = static_cast<wasmtime_valkind_t>(src.kind);
    switch (src.kind) {
        case WASM_I32:
            dst.of.i32 = src.of.i32;
            break;
        case WASM_I64:
            dst.of.i64 = src.of.i64;
            break;
        case WASM_F32:
            dst.of.f32 = src.of.f32;
            break;
        case WASM_F64:
            dst.of.f64 = src.of.f64;
            break;
        case WASM_FUNCREF:
            dst.of.funcref = *reinterpret_cast<wasmtime_func_t*>(src.of.ref);
            break;
        default:
            std::memset(&dst.of, 0, sizeof(dst.of));
            break;
    }
}

// Get error message from wasmtime_error_t
static std::string get_error_message(wasmtime_error_t* error) {
    wasm_name_t name;
    wasmtime_error_message(error, &name);
    std::string msg(name.data, name.size);
    wasm_byte_vec_delete(&name);
    return msg;
}

} // namespace

WasmEngine::WasmEngine(const WasmConfig& config) : config_(config) {
    wasm_config_t* wasm_config = wasm_config_new();
    CHECK_WASM(wasm_config, "Failed to create wasm config");

    wasmtime_config_consume_fuel_set(wasm_config, true);
    wasmtime_config_epoch_interruption_set(wasm_config, true);

    // Configure memory limits
    wasmtime_config_memory_reservation_set(wasm_config, config.max_memory_bytes);
    wasmtime_config_memory_guard_size_set(wasm_config, 64 * 1024); // 64KB guard pages

    wasm_engine_t* eng = wasm_engine_new_with_config(wasm_config);
    if (!eng) {
        wasm_config_delete(wasm_config);
        throw std::runtime_error("Failed to create wasm engine");
    }
    engine_ = eng;
    // Engine takes ownership of config, don't delete manually

    wasmtime_store_t* store = wasmtime_store_new(engine_, nullptr, nullptr);
    CHECK_WASM(store, "Failed to create wasmtime store");
    store_ = store;

    linker_ = wasmtime_linker_new(engine_);
    CHECK_WASM(linker_, "Failed to create linker");

    // Set initial fuel to 0 (will be set per execution)
    wasmtime_context_set_fuel(wasmtime_store_context(store_), 0);
    fuel_consumed_ = 0;
}

WasmEngine::~WasmEngine() {
    if (linker_) wasmtime_linker_delete(linker_);
    if (store_) wasmtime_store_delete(store_);
    if (engine_) wasm_engine_delete(engine_);
}

void WasmEngine::consume_fuel(uint64_t amount) {
    // Get current fuel, subtract amount, set new fuel
    uint64_t current_fuel = 0;
    wasmtime_error_t* error = wasmtime_context_get_fuel(wasmtime_store_context(store_), &current_fuel);
    if (!error && current_fuel >= amount) {
        wasmtime_context_set_fuel(wasmtime_store_context(store_), current_fuel - amount);
        fuel_consumed_ += amount;
    }
    if (error) wasmtime_error_delete(error);
}

void WasmEngine::reset_fuel() {
    wasmtime_context_set_fuel(wasmtime_store_context(store_), 0);
    fuel_consumed_ = 0;
}

uint64_t WasmEngine::fuel_remaining() const noexcept {
    uint64_t remaining = 0;
    wasmtime_error_t* error = wasmtime_context_get_fuel(wasmtime_store_context(store_), &remaining);
    if (error) {
        wasmtime_error_delete(error);
        return 0;
    }
    return remaining;
}

uint64_t WasmEngine::fuel_consumed_this_execution() const noexcept {
    return fuel_consumed_;
}

void WasmEngine::set_execution_limits(uint64_t max_time_ns, uint64_t max_memory_bytes) {
    // Set fuel for this execution
    wasmtime_context_set_fuel(wasmtime_store_context(store_), config_.fuel_per_execution);
    fuel_consumed_ = 0;
    
    // Set epoch deadline based on max_time_ns
    // epoch_duration_ns = 10ms default, so ticks = max_time_ns / epoch_duration_ns
    uint64_t ticks = max_time_ns / config_.epoch_duration_ns;
    if (ticks == 0) ticks = 1;
    wasmtime_context_set_epoch_deadline(wasmtime_store_context(store_), ticks);
}

void WasmEngine::epoch_interrupt() {
    // Set epoch deadline to 0 to interrupt immediately
    wasmtime_context_set_epoch_deadline(wasmtime_store_context(store_), 0);
}

void WasmEngine::increment_epoch() {
    wasmtime_engine_increment_epoch(engine_);
}

WasmModule::~WasmModule() {
    if (module_) wasmtime_module_delete(module_);
}

Result<WasmModule> WasmModule::from_bytes(WasmEngine& engine, BytesView wasm_bytes) {
    wasmtime_module_t* module = nullptr;
    wasmtime_error_t* error = wasmtime_module_new(
        engine.engine(),
        reinterpret_cast<const uint8_t*>(wasm_bytes.data()),
        wasm_bytes.size(),
        &module
    );

    if (error) {
        std::string msg = get_error_message(error);
        wasmtime_error_delete(error);
        return SMO_ERR_RUNTIME(100, Error, NoRetry, None,
                               "Failed to compile WASM module: " + msg);
    }

    if (!module) {
        return SMO_ERR_RUNTIME(100, Error, NoRetry, None,
                               "Failed to compile WASM module");
    }

    return WasmModule(module);
}

bool WasmModule::has_export(std::string_view name) const {
    wasm_exporttype_vec_t exports;
    wasmtime_module_exports(module_, &exports);
    bool found = false;
    for (size_t i = 0; i < exports.size; ++i) {
        const wasm_name_t* export_name = wasm_exporttype_name(exports.data[i]);
        if (export_name && export_name->size == name.size() && std::memcmp(export_name->data, name.data(), name.size()) == 0) {
            found = true;
            break;
        }
    }
    wasm_exporttype_vec_delete(&exports);
    return found;
}

std::vector<std::pair<std::string, std::string>> WasmModule::imports() const {
    std::vector<std::pair<std::string, std::string>> result;
    wasm_importtype_vec_t imports;
    wasmtime_module_imports(module_, &imports);
    for (size_t i = 0; i < imports.size; ++i) {
        const wasm_name_t* module_name = wasm_importtype_module(imports.data[i]);
        const wasm_name_t* name = wasm_importtype_name(imports.data[i]);
        result.emplace_back(
            module_name && module_name->size > 0 ? std::string(module_name->data, module_name->size) : "",
            name && name->size > 0 ? std::string(name->data, name->size) : ""
        );
    }
    wasm_importtype_vec_delete(&imports);
    return result;
}

std::vector<std::string> WasmModule::exports() const {
    std::vector<std::string> result;
    wasm_exporttype_vec_t exports;
    wasmtime_module_exports(module_, &exports);
    for (size_t i = 0; i < exports.size; ++i) {
        const wasm_name_t* name = wasm_exporttype_name(exports.data[i]);
        if (name && name->size > 0) {
            result.emplace_back(name->data, name->size);
        }
    }
    wasm_exporttype_vec_delete(&exports);
    return result;
}

Result<void> WasmModule::validate_imports(const std::unordered_map<std::string, wasm_extern_t*>& host_functions) const {
    wasm_importtype_vec_t imports;
    wasmtime_module_imports(module_, &imports);
    for (size_t i = 0; i < imports.size; ++i) {
        const wasm_name_t* module_name = wasm_importtype_module(imports.data[i]);
        const wasm_name_t* name = wasm_importtype_name(imports.data[i]);
        if (!module_name || !name || module_name->size == 0 || name->size == 0) continue;

        std::string key(module_name->data, module_name->size);
        key += ".";
        key += std::string(name->data, name->size);
        if (host_functions.find(key) == host_functions.end()) {
            wasm_importtype_vec_delete(&imports);
            return SMO_ERR_RUNTIME(101, Error, NoRetry, None,
                                   "Missing host function for import: " + key);
        }
    }
    wasm_importtype_vec_delete(&imports);
    return {};
}



Result<WasmInstance> WasmInstance::instantiate(
    WasmEngine& engine,
    const WasmModule& module,
    const std::unordered_map<std::string, wasm_extern_t*>& host_functions) {

    wasmtime_context_t* context = engine.context();
    wasmtime_instance_t instance;
    wasm_trap_t* trap = nullptr;
    wasmtime_error_t* error = nullptr;

    std::printf("DEBUG WasmInstance::instantiate: host_functions.size() = %zu\n", host_functions.size()); fflush(stdout);

    // Solution 1 (Local Memory Definition & Export):
    // Modules now DEFINE memory locally and EXPORT it.
    // No memory import means we can use direct instantiation.
    // Host functions are registered with the linker before this call.
    std::printf("DEBUG: Using linker instantiation (host functions only, no memory import)\n"); fflush(stdout);
    wasmtime_linker_t* linker = engine.linker();
    std::printf("DEBUG: Calling wasmtime_linker_instantiate\n"); fflush(stdout);
    error = wasmtime_linker_instantiate(linker, context, module.module(), &instance, &trap);
    std::printf("DEBUG: wasmtime_linker_instantiate returned\n"); fflush(stdout);

    if (error) {
        std::string msg = get_error_message(error);
        wasmtime_error_delete(error);
        if (trap) wasm_trap_delete(trap);
        return SMO_ERR_RUNTIME(102, Error, NoRetry, None,
                               "Failed to instantiate WASM module: " + msg);
    }
    if (trap) {
        wasm_trap_delete(trap);
        return SMO_ERR_RUNTIME(102, Error, NoRetry, None,
                               "WASM module instantiation trapped");
    }

    return WasmInstance(instance, &engine);
}

Result<std::vector<wasm_val_t>> WasmInstance::call(
    const std::string& func_name,
    const std::vector<wasm_val_t>& args) {

    wasmtime_extern_t extern_val;
    wasmtime_context_t* context = engine_->context();
    bool ok = wasmtime_instance_export_get(context, &instance_, func_name.c_str(), func_name.size(), &extern_val);
    if (!ok) {
        return SMO_ERR_RUNTIME(103, Error, NoRetry, None,
                               "Export not found: " + func_name);
    }

    if (extern_val.kind != WASMTIME_EXTERN_FUNC) {
        wasmtime_extern_delete(&extern_val);
        return SMO_ERR_RUNTIME(103, Error, NoRetry, None,
                               "Export is not a function: " + func_name);
    }

    wasmtime_func_t* func = &extern_val.of.func;

    std::vector<wasmtime_val_t> wasmtime_args(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
        wasm_to_wasmtime_val(args[i], wasmtime_args[i]);
    }

    std::vector<wasmtime_val_t> wasmtime_results(16);
    size_t nresults = wasmtime_results.size();

    wasm_trap_t* trap = nullptr;
    wasmtime_error_t* error = wasmtime_func_call(
        context, func, wasmtime_args.data(), wasmtime_args.size(),
        wasmtime_results.data(), nresults, &trap
    );

    if (error) {
        std::string msg = get_error_message(error);
        wasmtime_error_delete(error);
        wasmtime_extern_delete(&extern_val);
        if (trap) wasm_trap_delete(trap);
        return SMO_ERR_RUNTIME(104, Error, NoRetry, None,
                               "Function call failed: " + msg);
    }
    if (trap) {
        wasm_trap_delete(trap);
        wasmtime_extern_delete(&extern_val);
        return SMO_ERR_RUNTIME(104, Error, NoRetry, None,
                               "Function call trapped");
    }

    std::vector<wasm_val_t> results;
    results.reserve(nresults);
    for (size_t i = 0; i < nresults; ++i) {
        wasm_val_t val;
        wasmtime_to_wasm_val(wasmtime_results[i], val);
        results.push_back(val);
        wasmtime_val_unroot(&wasmtime_results[i]);
    }

    wasmtime_extern_delete(&extern_val);
    return results;
}

Result<wasm_val_t> WasmInstance::get_global(std::string_view name) {
    wasmtime_extern_t extern_val;
    wasmtime_context_t* context = engine_->context();
    bool ok = wasmtime_instance_export_get(context, &instance_, name.data(), name.size(), &extern_val);
    if (!ok || extern_val.kind != WASMTIME_EXTERN_GLOBAL) {
        return SMO_ERR_RUNTIME(103, Error, NoRetry, None,
                               "Global not found: " + std::string(name));
    }

    wasmtime_val_t wasmtime_val;
    wasmtime_global_get(context, &extern_val.of.global, &wasmtime_val);

    wasm_val_t val;
    wasmtime_to_wasm_val(wasmtime_val, val);

    wasmtime_val_unroot(&wasmtime_val);
    wasmtime_extern_delete(&extern_val);

    return val;
}

Result<wasmtime_memory_t*> WasmInstance::get_memory() {
    wasmtime_extern_t extern_val;
    wasmtime_context_t* context = engine_->context();
    bool ok = wasmtime_instance_export_get(context, &instance_, "memory", 6, &extern_val);
    if (!ok || extern_val.kind != WASMTIME_EXTERN_MEMORY) {
        return SMO_ERR_RUNTIME(105, Error, NoRetry, None, "Memory export not found");
    }

    // wasmtime_memory_t is an opaque pointer type (wasmtime_memory*)
    // Store it and return pointer
    static thread_local wasmtime_memory_t mem_storage;
    mem_storage = extern_val.of.memory;
    wasmtime_extern_delete(&extern_val);
    return &mem_storage;
}

} // namespace smo::runtime::wasm