#include "compiler/wasm/wasm_emitter.hpp"
#include "core/runtime/wasm/wasm_host_function_names.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace smo::compiler::wasm {

namespace {

// WASM value types
constexpr uint8_t VALTYPE_I32 = 0x7F;
constexpr uint8_t VALTYPE_I64 = 0x7E;
constexpr uint8_t VALTYPE_F32 = 0x7D;
constexpr uint8_t VALTYPE_F64 = 0x7C;
constexpr uint8_t VALTYPE_V128 = 0x7B;
constexpr uint8_t VALTYPE_FUNCREF = 0x70;
constexpr uint8_t VALTYPE_EXTERNREF = 0x6F;

// WASM section IDs
constexpr uint8_t SECTION_CUSTOM = 0;
constexpr uint8_t SECTION_TYPE = 1;
constexpr uint8_t SECTION_IMPORT = 2;
constexpr uint8_t SECTION_FUNCTION = 3;
constexpr uint8_t SECTION_TABLE = 4;
constexpr uint8_t SECTION_MEMORY = 5;
constexpr uint8_t SECTION_GLOBAL = 6;
constexpr uint8_t SECTION_EXPORT = 7;
constexpr uint8_t SECTION_START = 8;
constexpr uint8_t SECTION_ELEMENT = 9;
constexpr uint8_t SECTION_CODE = 10;
constexpr uint8_t SECTION_DATA = 11;

// WASM opcodes
constexpr uint8_t OP_UNREACHABLE = 0x00;
constexpr uint8_t OP_NOP = 0x01;
constexpr uint8_t OP_BLOCK = 0x02;
constexpr uint8_t OP_LOOP = 0x03;
constexpr uint8_t OP_IF = 0x04;
constexpr uint8_t OP_ELSE = 0x05;
constexpr uint8_t OP_END = 0x0B;
constexpr uint8_t OP_BR = 0x0C;
constexpr uint8_t OP_BR_IF = 0x0D;
constexpr uint8_t OP_BR_TABLE = 0x0E;
constexpr uint8_t OP_RETURN = 0x0F;
constexpr uint8_t OP_CALL = 0x10;
constexpr uint8_t OP_CALL_INDIRECT = 0x11;
constexpr uint8_t OP_DROP = 0x1A;
constexpr uint8_t OP_SELECT = 0x1B;
constexpr uint8_t OP_LOCAL_GET = 0x20;
constexpr uint8_t OP_LOCAL_SET = 0x21;
constexpr uint8_t OP_LOCAL_TEE = 0x22;
constexpr uint8_t OP_GLOBAL_GET = 0x23;
constexpr uint8_t OP_GLOBAL_SET = 0x24;
constexpr uint8_t OP_I32_LOAD = 0x28;
constexpr uint8_t OP_I64_LOAD = 0x29;
constexpr uint8_t OP_F32_LOAD = 0x2A;
constexpr uint8_t OP_F64_LOAD = 0x2B;
constexpr uint8_t OP_I32_STORE = 0x36;
constexpr uint8_t OP_I64_STORE = 0x37;
constexpr uint8_t OP_MEMORY_SIZE = 0x3F;
constexpr uint8_t OP_MEMORY_GROW = 0x40;
constexpr uint8_t OP_I32_CONST = 0x41;
constexpr uint8_t OP_I64_CONST = 0x42;
constexpr uint8_t OP_F32_CONST = 0x43;
constexpr uint8_t OP_F64_CONST = 0x44;
constexpr uint8_t OP_I32_EQZ = 0x45;
constexpr uint8_t OP_I32_EQ = 0x46;
constexpr uint8_t OP_I32_NE = 0x47;
constexpr uint8_t OP_I32_LT_S = 0x48;
constexpr uint8_t OP_I32_LT_U = 0x49;
constexpr uint8_t OP_I32_GT_S = 0x4A;
constexpr uint8_t OP_I32_GT_U = 0x4B;
constexpr uint8_t OP_I32_LE_S = 0x4C;
constexpr uint8_t OP_I32_LE_U = 0x4D;
constexpr uint8_t OP_I32_GE_S = 0x4E;
constexpr uint8_t OP_I32_GE_U = 0x4F;

// Block types
constexpr uint8_t BLOCKTYPE_VOID = 0x40;  // 0x40 = empty result

// Module magic and version
constexpr uint32_t WASM_MAGIC = 0x6D736100;  // "\0asm"
constexpr uint32_t WASM_VERSION = 1;

} // anonymous namespace

WasmEmitter::WasmEmitter(const WasmEmitterConfig& config) : config_(config) {
    // Pre-define function types for host functions
    // Each host function has a unique type signature

    // We'll build func_types_ dynamically based on imports
    // For now, reserve space
    func_types_.reserve(config_.imports.size() + 5);  // +5 for local functions
}

Result<std::vector<uint8_t>> WasmEmitter::emit(const SmirModule& smir) {
    binary_.clear();
    local_indices_.clear();
    local_types_.clear();
    import_func_indices_.clear();
    local_func_indices_.clear();
    func_types_.clear();

    // Write module header: magic + version (raw bytes, not LEB128)
    // Magic: \0asm (0x00, 0x61, 0x73, 0x6D)
    write_byte(0x00);
    write_byte(0x61);
    write_byte(0x73);
    write_byte(0x6D);
    // Version: 1 (little-endian uint32)
    write_byte(0x01);
    write_byte(0x00);
    write_byte(0x00);
    write_byte(0x00);

    // Emit all sections
    emit_type_section();
    emit_import_section();
    emit_function_section();
    emit_memory_section();
    emit_export_section();
    emit_code_section(smir);

    return binary_;
}

void WasmEmitter::write_uleb128(uint64_t val, std::vector<uint8_t>* out) {
    auto& target = out ? *out : binary_;
    do {
        uint8_t byte = val & 0x7F;
        val >>= 7;
        if (val != 0) byte |= 0x80;
        target.push_back(byte);
    } while (val != 0);
}

void WasmEmitter::write_sleb128(int64_t val, std::vector<uint8_t>* out) {
    auto& target = out ? *out : binary_;
    bool more = true;
    while (more) {
        uint8_t byte = val & 0x7F;
        val >>= 7;
        bool sign_bit = (byte & 0x40) != 0;
        more = !((val == 0 && !sign_bit) || (val == -1 && sign_bit));
        if (more) byte |= 0x80;
        target.push_back(byte);
    }
}

void WasmEmitter::write_bytes(const std::vector<uint8_t>& data, std::vector<uint8_t>* out) {
    auto& target = out ? *out : binary_;
    target.insert(target.end(), data.begin(), data.end());
}

void WasmEmitter::write_byte(uint8_t byte, std::vector<uint8_t>* out) {
    auto& target = out ? *out : binary_;
    target.push_back(byte);
}

void WasmEmitter::write_section(uint8_t id, const std::vector<uint8_t>& payload) {
    write_byte(id);
    write_uleb128(static_cast<uint64_t>(payload.size()));
    write_bytes(payload);
}

void WasmEmitter::emit_type_section() {
    std::vector<uint8_t> payload;

    // Count: number of function types
    // First, add types for all imported host functions
    for (const auto& imp : config_.imports) {
        import_func_indices_[imp.name] = static_cast<uint32_t>(func_types_.size());
        func_types_.push_back({imp.param_types, imp.result_types});
    }

    // Add types for local functions (execute, initialize, shutdown, validate, metadata)
    // execute: (param i32 i32) (result i32 i32) - input_ptr, input_len -> output_ptr, output_len
    local_func_indices_["execute"] = static_cast<uint32_t>(func_types_.size());
    func_types_.push_back({{VALTYPE_I32, VALTYPE_I32}, {VALTYPE_I32, VALTYPE_I32}});

    if (config_.metadata.has_initialize) {
        local_func_indices_["initialize"] = static_cast<uint32_t>(func_types_.size());
        func_types_.push_back({{VALTYPE_I32, VALTYPE_I32}, {VALTYPE_I32}});
    }

    local_func_indices_["shutdown"] = static_cast<uint32_t>(func_types_.size());
    func_types_.push_back({{}, {VALTYPE_I32}});

    if (config_.metadata.has_validate) {
        local_func_indices_["validate"] = static_cast<uint32_t>(func_types_.size());
        func_types_.push_back({{VALTYPE_I32, VALTYPE_I32}, {VALTYPE_I32}});
    }

    local_func_indices_["metadata"] = static_cast<uint32_t>(func_types_.size());
    func_types_.push_back({{}, {VALTYPE_I32, VALTYPE_I32}});

    // Write count
    write_uleb128(func_types_.size(), &payload);

    // Write each function type
    for (const auto& ft : func_types_) {
        write_byte(0x60, &payload);  // func type tag
        write_uleb128(ft.params.size(), &payload);
        for (uint8_t t : ft.params) write_byte(t, &payload);
        write_uleb128(ft.results.size(), &payload);
        for (uint8_t t : ft.results) write_byte(t, &payload);
    }

    write_section(SECTION_TYPE, payload);
}

void WasmEmitter::emit_import_section() {
    std::vector<uint8_t> payload;

    // Count imports: host functions only (no memory import)
    write_uleb128(config_.imports.size(), &payload);

    // Host function imports only
    for (const auto& imp : config_.imports) {
        // Module name: "smo:v1"
        const std::string module_name = runtime::wasm::SMO_HOST_NAMESPACE;
        write_uleb128(module_name.size(), &payload);
        write_bytes(std::vector<uint8_t>(module_name.begin(), module_name.end()), &payload);

        // Field name: function name
        write_uleb128(imp.name.size(), &payload);
        write_bytes(std::vector<uint8_t>(imp.name.begin(), imp.name.end()), &payload);

        // Kind: 0 = func
        write_byte(0x00, &payload);

        // Type index
        auto it = import_func_indices_.find(imp.name);
        uint32_t type_idx = (it != import_func_indices_.end()) ? it->second : 0;
        write_uleb128(type_idx, &payload);
    }

    write_section(SECTION_IMPORT, payload);
}

void WasmEmitter::emit_function_section() {
    std::vector<uint8_t> payload;

    // Count of local functions (not imports)
    uint32_t local_func_count = 0;
    if (local_func_indices_.count("execute")) local_func_count++;
    if (local_func_indices_.count("initialize")) local_func_count++;
    if (local_func_indices_.count("shutdown")) local_func_count++;
    if (local_func_indices_.count("validate")) local_func_count++;
    if (local_func_indices_.count("metadata")) local_func_count++;

    write_uleb128(local_func_count, &payload);

    // Function type indices for local functions (in order they'll appear in code section)
    if (local_func_indices_.count("execute")) {
        write_uleb128(local_func_indices_["execute"], &payload);
    }
    if (local_func_indices_.count("initialize")) {
        write_uleb128(local_func_indices_["initialize"], &payload);
    }
    if (local_func_indices_.count("shutdown")) {
        write_uleb128(local_func_indices_["shutdown"], &payload);
    }
    if (local_func_indices_.count("validate")) {
        write_uleb128(local_func_indices_["validate"], &payload);
    }
    if (local_func_indices_.count("metadata")) {
        write_uleb128(local_func_indices_["metadata"], &payload);
    }

    write_section(SECTION_FUNCTION, payload);
}

void WasmEmitter::emit_memory_section() {
    std::vector<uint8_t> payload;

    // Memory count: 1 (defined locally, not imported)
    write_byte(1, &payload);

    // Memory type: limits (flags=1 for max)
    // Initial pages = max_memory_bytes / 64KB, but at least 1
    uint64_t max_mem = config_.metadata.max_memory_bytes;
    uint32_t initial_pages = std::max<uint32_t>(1, static_cast<uint32_t>(max_mem / 65536));
    uint32_t max_pages = initial_pages;  // Set max = initial for now

    std::printf("DEBUG emit_memory_section: max_mem=%llu, initial_pages=%u, max_pages=%u\n", (unsigned long long)max_mem, initial_pages, max_pages);

    write_byte(0x01, &payload);  // has max
    write_uleb128(initial_pages, &payload);
    write_uleb128(max_pages, &payload);
    std::printf("DEBUG emit_memory_section: payload size after write = %zu\n", payload.size());

    write_section(SECTION_MEMORY, payload);
}

void WasmEmitter::emit_export_section() {
    std::vector<uint8_t> payload;

    std::vector<std::pair<std::string, std::pair<uint8_t, uint32_t>>> exports;

    // execute function export
    exports.emplace_back("execute", std::make_pair(0x00, 0));  // func kind, index 0

    // initialize function export (if present)
    uint32_t func_idx = 1;
    if (config_.metadata.has_initialize) {
        exports.emplace_back("initialize", std::make_pair(0x00, func_idx++));
    }

    // shutdown function export
    exports.emplace_back("shutdown", std::make_pair(0x00, func_idx++));

    // validate function export (if present)
    if (config_.metadata.has_validate) {
        exports.emplace_back("validate", std::make_pair(0x00, func_idx++));
    }

    // metadata function export
    exports.emplace_back("metadata", std::make_pair(0x00, func_idx++));

    // memory export (memory index 0)
    exports.emplace_back("memory", std::make_pair(0x02, 0));  // memory kind, index 0

    write_uleb128(exports.size(), &payload);

    for (const auto& exp : exports) {
        write_uleb128(exp.first.size(), &payload);
        write_bytes(std::vector<uint8_t>(exp.first.begin(), exp.first.end()), &payload);
        write_byte(exp.second.first, &payload);  // kind
        write_uleb128(exp.second.second, &payload);  // index
    }

    write_section(SECTION_EXPORT, payload);
}

void WasmEmitter::emit_code_section(const SmirModule& smir) {
    std::vector<uint8_t> payload;

    // Count of function bodies (local functions only)
    uint32_t local_func_count = 0;
    if (local_func_indices_.count("execute")) local_func_count++;
    if (local_func_indices_.count("initialize")) local_func_count++;
    if (local_func_indices_.count("shutdown")) local_func_count++;
    if (local_func_indices_.count("validate")) local_func_count++;
    if (local_func_indices_.count("metadata")) local_func_count++;

    write_uleb128(local_func_count, &payload);

    // Emit each function body
    // execute
    if (local_func_indices_.count("execute")) {
        std::vector<uint8_t> func_body;
        emit_function_body(smir, "execute", func_body);
        write_uleb128(func_body.size(), &payload);
        write_bytes(func_body, &payload);
    }

    // initialize
    if (local_func_indices_.count("initialize")) {
        std::vector<uint8_t> func_body;
        emit_function_body(smir, "initialize", func_body);
        write_uleb128(func_body.size(), &payload);
        write_bytes(func_body, &payload);
    }

    // shutdown
    {
        std::vector<uint8_t> func_body;
        emit_function_body(smir, "shutdown", func_body);
        write_uleb128(func_body.size(), &payload);
        write_bytes(func_body, &payload);
    }

    // validate
    if (local_func_indices_.count("validate")) {
        std::vector<uint8_t> func_body;
        emit_function_body(smir, "validate", func_body);
        write_uleb128(func_body.size(), &payload);
        write_bytes(func_body, &payload);
    }

    // metadata
    {
        std::vector<uint8_t> func_body;
        emit_function_body(smir, "metadata", func_body);
        write_uleb128(func_body.size(), &payload);
        write_bytes(func_body, &payload);
    }

    write_section(SECTION_CODE, payload);
}

void WasmEmitter::emit_function_body(const SmirModule& smir, const std::string& func_name, std::vector<uint8_t>& func_body) {
    // Save current binary_ and redirect to func_body
    auto saved_binary = std::move(binary_);
    binary_ = std::move(func_body);
    
    local_indices_.clear();
    local_types_.clear();
    std::vector<uint8_t> param_types;

    if (func_name == "execute") {
        // Function signature: (param i32 i32) (result i32 i32)
        local_indices_["input_ptr"] = 0;
        param_types.push_back(VALTYPE_I32);
        local_indices_["input_len"] = 1;
        param_types.push_back(VALTYPE_I32);
    } else if (func_name == "initialize") {
        // Function signature: (param i32 i32) (result i32)
        local_indices_["config_ptr"] = 0;
        param_types.push_back(VALTYPE_I32);
        local_indices_["config_len"] = 1;
        param_types.push_back(VALTYPE_I32);
    } else if (func_name == "validate") {
        // Function signature: (param i32 i32) (result i32)
        local_indices_["input_ptr"] = 0;
        param_types.push_back(VALTYPE_I32);
        local_indices_["input_len"] = 1;
        param_types.push_back(VALTYPE_I32);
    }
    // shutdown and metadata have no params

    // Emit locals declaration (only additional locals, not params)
    emit_locals_decl(local_types_);

    // Execute SMIR blocks
    for (const auto& block : smir.blocks) {
        emit_block(block);
    }

    // Default return based on function
    if (func_name == "execute") {
        write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
        write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
    } else if (func_name == "metadata") {
        write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
        write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
    } else {
        write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
    }
    write_byte(OP_RETURN);
    write_byte(OP_END);

    // Restore
    func_body = std::move(binary_);
    binary_ = std::move(saved_binary);
}

void WasmEmitter::emit_locals_decl(const std::vector<uint8_t>& local_types) {
    // Group locals by type for compact encoding
    std::map<uint8_t, uint32_t> type_counts;
    for (uint8_t t : local_types) {
        type_counts[t]++;
    }

    write_uleb128(static_cast<uint64_t>(type_counts.size()));
    for (const auto& [type, count] : type_counts) {
        write_uleb128(static_cast<uint64_t>(count));
        write_byte(type);
    }
}

void WasmEmitter::emit_block(const SmirBasicBlock& block) {
    for (const auto& instr : block.instructions) {
        emit_instruction(instr);
    }
}

void WasmEmitter::emit_instruction(const SmirInstruction& instr) {
    using Op = SmirOpcode;

    switch (instr.opcode) {
        case Op::Nop:
            write_byte(OP_NOP);
            break;

        case Op::Call: {
            // Call host function or local function
            std::string func_name = instr.lhs.value;
            auto import_it = import_func_indices_.find(func_name);
            auto local_it = local_func_indices_.find(func_name);

            if (import_it != import_func_indices_.end()) {
                // Host function call
                write_byte(OP_CALL);
                write_uleb128(import_it->second);
            } else if (local_it != local_func_indices_.end()) {
                // Local function call (adjust index: imports come first)
                uint32_t import_count = static_cast<uint32_t>(config_.imports.size());
                write_byte(OP_CALL);
                write_uleb128(import_count + local_it->second);
            } else {
                // Unknown function - for MVP emit unreachable
                write_byte(OP_UNREACHABLE);
            }
            break;
        }

        case Op::Load: {
            // Load from memory or local
            // dst = load(src, offset)
            // For MVP: if lhs is a local, do local.get
            if (instr.lhs.type == SmirOperand::Identifier) {
                uint32_t idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(idx);
            } else if (instr.lhs.type == SmirOperand::Temp) {
                uint32_t idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(idx);
            }
            // If rhs is present, treat as offset for memory load
            if (instr.rhs.type != SmirOperand::None) {
                // Memory load with offset
                if (instr.rhs.type == SmirOperand::Literal) {
                    write_byte(OP_I32_CONST);
                    write_sleb128(std::stoll(instr.rhs.value));
                }
                write_byte(OP_I32_LOAD);
                write_byte(0);  // align
                write_byte(0);  // offset
            }
            // Store result in dst if provided
            if (instr.dst.type != SmirOperand::None) {
                uint32_t dst_idx = get_local_index(instr.dst.value);
                write_byte(OP_LOCAL_SET);
                write_uleb128(dst_idx);
            }
            break;
        }

        case Op::Store: {
            // Store to memory or local
            // store(dst, value)
            // Evaluate value (rhs) first
            if (instr.rhs.type == SmirOperand::Literal) {
                write_byte(OP_I32_CONST);
                write_sleb128(std::stoll(instr.rhs.value));
            } else if (instr.rhs.type == SmirOperand::Identifier || instr.rhs.type == SmirOperand::Temp) {
                uint32_t idx = get_local_index(instr.rhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(idx);
            }

            // Store to destination
            if (instr.lhs.type == SmirOperand::Identifier || instr.lhs.type == SmirOperand::Temp) {
                uint32_t idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_SET);
                write_uleb128(idx);
            }
            break;
        }

        case Op::Cond: {
            // Conditional: if (cond) then_block else else_block end
            // For MVP: cond is in lhs, then_block in annotation, else in rhs?
            // Simplified: emit if-else based on lhs value
            if (instr.lhs.type == SmirOperand::Literal) {
                write_byte(OP_I32_CONST);
                write_sleb128(std::stoll(instr.lhs.value));
            } else if (instr.lhs.type == SmirOperand::Identifier || instr.lhs.type == SmirOperand::Temp) {
                uint32_t idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(idx);
            }

            write_byte(OP_IF);
            write_byte(BLOCKTYPE_VOID);

            // Then branch - for MVP, we don't have nested blocks in SMIR
            // In real implementation, we'd parse the annotation/rhs for block labels

            write_byte(OP_ELSE);
            // Else branch

            write_byte(OP_END);
            break;
        }

        case Op::Seq:
            // Sequential - implicit, no opcode needed
            break;

        case Op::Parallel:
            // Skip for MVP
            break;

        case Op::BindInput: {
            // Bind input to local
            // dst = input
            if (instr.dst.type != SmirOperand::None) {
                // For execute function, input is in local 0,1
                // We'll just copy to dst local
                write_byte(OP_LOCAL_GET);
                write_uleb128(0);  // input_ptr
                write_byte(OP_LOCAL_GET);
                write_uleb128(1);  // input_len
                // Call host deserialize? For MVP, just store ptr/len
                uint32_t dst_idx = get_local_index(instr.dst.value);
                write_byte(OP_LOCAL_SET);
                write_uleb128(dst_idx);
            }
            break;
        }

        case Op::BindOutput: {
            // Bind output from local
            // output = src
            if (instr.lhs.type != SmirOperand::None) {
                uint32_t src_idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(src_idx);
                // Return value - for execute function, this sets return values
            }
            break;
        }

        case Op::Literal: {
            // Push literal value
            if (instr.lhs.type == SmirOperand::Literal) {
                // Determine type from value format
                // For MVP, assume i32
                write_byte(OP_I32_CONST);
                write_sleb128(std::stoll(instr.lhs.value));
            }
            // Store in dst if provided
            if (instr.dst.type != SmirOperand::None) {
                uint32_t dst_idx = get_local_index(instr.dst.value);
                write_byte(OP_LOCAL_SET);
                write_uleb128(dst_idx);
            }
            break;
        }

        case Op::Move: {
            // Move: dst = src
            if (instr.lhs.type != SmirOperand::None) {
                uint32_t src_idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(src_idx);
            }
            if (instr.dst.type != SmirOperand::None) {
                uint32_t dst_idx = get_local_index(instr.dst.value);
                write_byte(OP_LOCAL_SET);
                write_uleb128(dst_idx);
            }
            break;
        }

        case Op::Assert: {
            // Assert: if (!cond) unreachable
            if (instr.lhs.type == SmirOperand::Literal) {
                write_byte(OP_I32_CONST);
                write_sleb128(std::stoll(instr.lhs.value));
            } else if (instr.lhs.type == SmirOperand::Identifier || instr.lhs.type == SmirOperand::Temp) {
                uint32_t idx = get_local_index(instr.lhs.value);
                write_byte(OP_LOCAL_GET);
                write_uleb128(idx);
            }
            write_byte(OP_IF);
            write_byte(BLOCKTYPE_VOID);
            write_byte(OP_UNREACHABLE);
            write_byte(OP_END);
            break;
        }

        case Op::Debug: {
            // Debug: call host debug function
            auto it = import_func_indices_.find(runtime::wasm::HF_LOGGER_DEBUG);
            if (it != import_func_indices_.end()) {
                // Push debug message (for MVP, empty string)
                write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
                write_byte(OP_I32_CONST); write_uleb128(static_cast<uint64_t>(0));
                write_byte(OP_CALL);
                write_uleb128(static_cast<uint64_t>(it->second));
            }
            break;
        }
    }
}

uint32_t WasmEmitter::get_import_type_index(const std::string& name) const {
    auto it = import_func_indices_.find(name);
    return (it != import_func_indices_.end()) ? it->second : 0;
}

uint32_t WasmEmitter::get_local_index(const std::string& name) {
    auto it = local_indices_.find(name);
    if (it != local_indices_.end()) {
        return it->second;
    }
    // Allocate new local (default to i32)
    return allocate_local(VALTYPE_I32);
}

uint32_t WasmEmitter::allocate_local(uint8_t wasm_type) {
    uint32_t idx = static_cast<uint32_t>(local_types_.size());
    local_indices_[std::to_string(idx)] = idx;  // Use numeric name for temps
    local_types_.push_back(wasm_type);
    return idx;
}

} // namespace smo::compiler::wasm