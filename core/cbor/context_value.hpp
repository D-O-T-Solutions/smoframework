#pragma once

// RFC 0043: Unified CBOR Pipeline
// ContextValue recursive variant, SchemaRegistry validation, content-type byte

#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/bootstrap/cbor.hpp"

#include <variant>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <cstdint>

namespace smo::cbor {

// Forward declarations
struct ContextValue;
using ContextArray = std::vector<ContextValue>;
using ContextMap = std::map<std::string, ContextValue>;

// RFC 0043 §2.3: ContextValue recursive variant
// Supports: nil, bool, int, float, string, bytes, array, map
struct ContextValue
{
    enum class Type : uint8_t
    {
        Nil = 0,
        Bool = 1,
        Int = 2,
        Float = 3,
        String = 4,
        Bytes = 5,
        Array = 6,
        Map = 7,
    };

    // Storage for the variant
    std::variant<
        std::monostate,           // Nil
        bool,                     // Bool
        int64_t,                  // Int
        double,                   // Float
        std::string,              // String
        Bytes,                    // Bytes
        ContextArray,             // Array
        ContextMap                // Map
    > value;

    ContextValue() = default;
    ContextValue(std::monostate) : value(std::monostate{}) {}
    ContextValue(bool v) : value(v) {}
    ContextValue(int64_t v) : value(v) {}
    ContextValue(double v) : value(v) {}
    ContextValue(const std::string& v) : value(v) {}
    ContextValue(std::string&& v) : value(std::move(v)) {}
    ContextValue(const char* v) : value(std::string(v)) {}
    ContextValue(const Bytes& v) : value(v) {}
    ContextValue(Bytes&& v) : value(std::move(v)) {}
    ContextValue(const ContextArray& v) : value(v) {}
    ContextValue(ContextArray&& v) : value(std::move(v)) {}
    ContextValue(const ContextMap& v) : value(v) {}
    ContextValue(ContextMap&& v) : value(std::move(v)) {}

    Type type() const noexcept
    {
        return static_cast<Type>(value.index());
    }

    bool is_nil() const noexcept { return std::holds_alternative<std::monostate>(value); }
    bool is_bool() const noexcept { return std::holds_alternative<bool>(value); }
    bool is_int() const noexcept { return std::holds_alternative<int64_t>(value); }
    bool is_float() const noexcept { return std::holds_alternative<double>(value); }
    bool is_string() const noexcept { return std::holds_alternative<std::string>(value); }
    bool is_bytes() const noexcept { return std::holds_alternative<Bytes>(value); }
    bool is_array() const noexcept { return std::holds_alternative<ContextArray>(value); }
    bool is_map() const noexcept { return std::holds_alternative<ContextMap>(value); }

    // Accessors
    bool as_bool() const noexcept { return std::get<bool>(value); }
    int64_t as_int() const noexcept { return std::get<int64_t>(value); }
    double as_float() const noexcept { return std::get<double>(value); }
    const std::string& as_string() const noexcept { return std::get<std::string>(value); }
    const Bytes& as_bytes() const noexcept { return std::get<Bytes>(value); }
    const ContextArray& as_array() const noexcept { return std::get<ContextArray>(value); }
    const ContextMap& as_map() const noexcept { return std::get<ContextMap>(value); }

    ContextArray& as_array_mut() noexcept { return std::get<ContextArray>(value); }
    ContextMap& as_map_mut() noexcept { return std::get<ContextMap>(value); }

    // Comparison
    bool operator==(const ContextValue& other) const noexcept
    {
        return value == other.value;
    }
    bool operator!=(const ContextValue& other) const noexcept
    {
        return !(*this == other);
    }
};

// RFC 0043 §2.2: Content-type byte for CBOR payloads
inline constexpr uint8_t kContentTypeContextValue = 0x01;
inline constexpr uint8_t kContentTypeContractInput = 0x02;
inline constexpr uint8_t kContentTypeContractResult = 0x03;
inline constexpr uint8_t kContentTypePacketPayload = 0x04;

// Encode ContextValue to CBOR
void encode_context_value(Encoder& enc, const ContextValue& val);

// Decode ContextValue from CBOR
Result<ContextValue> decode_context_value(Decoder& dec);

// Encode ContextValue to bytes (with content-type byte prefix)
Bytes encode_context_value_bytes(const ContextValue& val, uint8_t content_type = kContentTypeContextValue);

// Decode ContextValue from bytes (expects content-type byte prefix)
Result<ContextValue> decode_context_value_bytes(BytesView data, uint8_t expected_content_type = kContentTypeContextValue);

// ContractInput — input to contract execution
struct ContractInput
{
    std::string contract_id;
    std::string method;
    ContextValue params;  // Must be a Map
    std::string caller_id;
    int64_t timestamp{0};
    uint64_t nonce{0};

    // Encode to CBOR
    Bytes to_cbor() const;

    // Decode from CBOR
    static Result<ContractInput> from_cbor(BytesView data);
};

// ContractResult — output from contract execution
struct ContractResult
{
    enum class Status : uint8_t
    {
        Success = 0,
        Error = 1,
        Rejected = 2,
    };

    Status status{Status::Success};
    ContextValue result;      // Success value
    std::string error_code;   // Error code if failed
    std::string error_message; // Error message if failed
    int64_t gas_used{0};
    int64_t timestamp{0};

    // Encode to CBOR
    Bytes to_cbor() const;

    // Decode from CBOR
    static Result<ContractResult> from_cbor(BytesView data);
};

// SchemaRegistry — RFC 0043 §2.6: Schema validation
class SchemaRegistry
{
public:
    struct FieldSchema
    {
        std::string name;
        ContextValue::Type type;
        bool required{true};
        std::string description;
    };

    struct Schema
    {
        std::string name;
        std::string version;
        std::vector<FieldSchema> fields;
        std::map<std::string, Schema> nested_schemas;  // For nested map validation
    };

    SchemaRegistry() = default;

    // Register a schema
    Result<void> register_schema(const Schema& schema);

    // Validate a ContextValue (must be Map) against a registered schema
    Result<void> validate(const ContextValue& value, std::string_view schema_name) const;

    // Check if schema exists
    bool has_schema(std::string_view name) const;

    // Get schema by name
    std::optional<Schema> get_schema(std::string_view name) const;

    // List all registered schemas
    std::vector<std::string> list_schemas() const;

private:
    std::map<std::string, Schema> schemas_;
};

// Global schema registry instance
SchemaRegistry& schema_registry();

} // namespace smo::cbor