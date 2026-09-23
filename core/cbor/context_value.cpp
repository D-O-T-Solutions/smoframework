#include "context_value.hpp"

#include <sstream>
#include <iomanip>
#include <cstring>

namespace smo::cbor {

// ── ContextValue CBOR Encoding ────────────────────────────────────────────

void encode_context_value(Encoder& enc, const ContextValue& val)
{
    switch (val.type())
    {
    case ContextValue::Type::Nil:
        // CBOR null = simple value 22 (major 7, additional info 22)
        enc.push_byte(0xF6);
        break;

    case ContextValue::Type::Bool:
        // CBOR true/false = simple value 21/20 (major 7, additional info 21/20)
        enc.push_byte(val.as_bool() ? 0xF5 : 0xF4);
        break;

    case ContextValue::Type::Int:
        enc.encode_int(val.as_int());
        break;

    case ContextValue::Type::Float:
        // Encode as IEEE 754 double (major 7, additional info 27)
        {
            double f = val.as_float();
            uint64_t bits;
            static_assert(sizeof(double) == sizeof(uint64_t));
            std::memcpy(&bits, &f, sizeof(double));
            uint8_t header = 0xFB; // major 7, ai 27 = 8-byte float
            enc.push_byte(header);
            for (int i = 7; i >= 0; --i)
            {
                enc.push_byte(static_cast<uint8_t>((bits >> (i * 8)) & 0xFF));
            }
        }
        break;

    case ContextValue::Type::String:
        enc.encode_string(val.as_string());
        break;

    case ContextValue::Type::Bytes:
        enc.encode_bytes(val.as_bytes());
        break;

    case ContextValue::Type::Array:
        {
            const auto& arr = val.as_array();
            enc.encode_array(arr.size());
            for (const auto& elem : arr)
            {
                encode_context_value(enc, elem);
            }
        }
        break;

    case ContextValue::Type::Map:
        {
            const auto& map = val.as_map();
            enc.encode_map(map.size());
            for (const auto& [key, elem] : map)
            {
                enc.encode_string(key);
                encode_context_value(enc, elem);
            }
        }
        break;
    }
}

// ── ContextValue CBOR Decoding ────────────────────────────────────────────

Result<ContextValue> decode_context_value(Decoder& dec)
{
    if (dec.done())
    {
        return SMO_ERR_PROTOCOL(700, Error, NoRetry, None, "CBOR: unexpected end of data");
    }

    uint8_t major = dec.peek_major();
    uint8_t ib = dec.current_view()[0];

    // Handle simple values (major 7)
    if (major == 7)
    {
        uint8_t ai = ib & 0x1F;
        if (ai == 20) // false
        {
            dec.advance(1);
            return ContextValue(false);
        }
        else if (ai == 21) // true
        {
            dec.advance(1);
            return ContextValue(true);
        }
        else if (ai == 22) // null
        {
            dec.advance(1);
            return ContextValue(std::monostate{});
        }
        else if (ai == 27) // float64
        {
            if (dec.remaining() < 9)
            {
                return SMO_ERR_PROTOCOL(700, Error, NoRetry, None, "CBOR: truncated float64");
            }
            dec.advance(1); // skip header
            auto view = dec.current_view();
            uint64_t bits = 0;
            for (int i = 0; i < 8; ++i)
            {
                bits = (bits << 8) | view[i];
            }
            dec.advance(8);
            double f;
            std::memcpy(&f, &bits, sizeof(double));
            return ContextValue(f);
        }
    }

    // Major 0: unsigned int
    if (major == 0)
    {
        auto u = dec.decode_uint();
        if (!u)
            return u.error();
        return ContextValue(static_cast<int64_t>(u.value()));
    }

    // Major 1: negative int
    if (major == 1)
    {
        auto i = dec.decode_int();
        if (!i)
            return i.error();
        return ContextValue(i.value());
    }

    // Major 2: byte string
    if (major == 2)
    {
        auto b = dec.decode_bytes();
        if (!b)
            return b.error();
        return ContextValue(Bytes(b.value().begin(), b.value().end()));
    }

    // Major 3: text string
    if (major == 3)
    {
        auto s = dec.decode_string();
        if (!s)
            return s.error();
        return ContextValue(std::move(s.value()));
    }

    // Major 4: array
    if (major == 4)
    {
        auto size_res = dec.decode_array_size();
        if (!size_res)
            return size_res.error();

        ContextArray arr;
        arr.reserve(size_res.value());
        for (size_t i = 0; i < size_res.value(); ++i)
        {
            auto elem = decode_context_value(dec);
            if (!elem)
                return elem.error();
            arr.push_back(std::move(elem.value()));
        }
        return ContextValue(std::move(arr));
    }

    // Major 5: map
    if (major == 5)
    {
        auto size_res = dec.decode_map_size();
        if (!size_res)
            return size_res.error();

        ContextMap map;
        for (size_t i = 0; i < size_res.value(); ++i)
        {
            // Key must be string
            auto key_res = dec.decode_string();
            if (!key_res)
                return key_res.error();

            auto val_res = decode_context_value(dec);
            if (!val_res)
                return val_res.error();

            map.emplace(std::move(key_res.value()), std::move(val_res.value()));
        }
        return ContextValue(std::move(map));
    }

    return SMO_ERR_PROTOCOL(708, Error, NoRetry, None,
                            "CBOR: unsupported major type " + std::to_string((int)major) + " for ContextValue");
}

// ── Encode/Decode with content-type byte ───────────────────────────────────

Bytes encode_context_value_bytes(const ContextValue& val, uint8_t content_type)
{
    Encoder enc;
    enc.push_byte(content_type);
    encode_context_value(enc, val);
    return enc.take();
}

Result<ContextValue> decode_context_value_bytes(BytesView data, uint8_t expected_content_type)
{
    if (data.empty())
    {
        return SMO_ERR_PROTOCOL(700, Error, NoRetry, None, "CBOR: empty data");
    }

    if (data[0] != expected_content_type)
    {
        return SMO_ERR_PROTOCOL(710, Error, NoRetry, None,
                                "CBOR: content-type mismatch (expected " + std::to_string(expected_content_type) +
                                ", got " + std::to_string(data[0]) + ")");
    }

    Decoder dec(data.subspan(1));
    return decode_context_value(dec);
}

// ── ContractInput CBOR ────────────────────────────────────────────────────

Bytes ContractInput::to_cbor() const
{
    Encoder enc;
    enc.push_byte(kContentTypeContractInput);

    // Map with fields: contract_id, method, params, caller_id, timestamp, nonce
    enc.encode_map(6);

    encode_string_key(enc, "contract_id");
    enc.encode_string(contract_id);

    encode_string_key(enc, "method");
    enc.encode_string(method);

    encode_string_key(enc, "params");
    encode_context_value(enc, params);

    encode_string_key(enc, "caller_id");
    enc.encode_string(caller_id);

    encode_string_key(enc, "timestamp");
    enc.encode_uint(static_cast<uint64_t>(timestamp));

    encode_string_key(enc, "nonce");
    enc.encode_uint(nonce);

    return enc.take();
}

Result<ContractInput> ContractInput::from_cbor(BytesView data)
{
    auto ctx_res = decode_context_value_bytes(data, kContentTypeContractInput);
    if (!ctx_res)
        return ctx_res.error();

    const auto& ctx = ctx_res.value();
    if (!ctx.is_map())
    {
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: expected map");
    }

    const auto& map = ctx.as_map();

    ContractInput input;

    auto it = map.find("contract_id");
    if (it == map.end() || !it->second.is_string())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing or invalid contract_id");
    input.contract_id = it->second.as_string();

    it = map.find("method");
    if (it == map.end() || !it->second.is_string())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing or invalid method");
    input.method = it->second.as_string();

    it = map.find("params");
    if (it == map.end())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing params");
    input.params = it->second;

    it = map.find("caller_id");
    if (it == map.end() || !it->second.is_string())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing or invalid caller_id");
    input.caller_id = it->second.as_string();

    it = map.find("timestamp");
    if (it == map.end() || !it->second.is_int())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing or invalid timestamp");
    input.timestamp = it->second.as_int();

    it = map.find("nonce");
    if (it == map.end() || !it->second.is_int())
        return SMO_ERR_PROTOCOL(711, Error, NoRetry, None, "ContractInput: missing or invalid nonce");
    input.nonce = static_cast<uint64_t>(it->second.as_int());

    return input;
}

// ── ContractResult CBOR ────────────────────────────────────────────────────

Bytes ContractResult::to_cbor() const
{
    Encoder enc;
    enc.push_byte(kContentTypeContractResult);

    // Map with fields: status, result, error_code, error_message, gas_used, timestamp
    enc.encode_map(6);

    encode_string_key(enc, "status");
    enc.encode_uint(static_cast<uint64_t>(status));

    encode_string_key(enc, "result");
    encode_context_value(enc, result);

    encode_string_key(enc, "error_code");
    enc.encode_string(error_code);

    encode_string_key(enc, "error_message");
    enc.encode_string(error_message);

    encode_string_key(enc, "gas_used");
    enc.encode_uint(static_cast<uint64_t>(gas_used));

    encode_string_key(enc, "timestamp");
    enc.encode_uint(static_cast<uint64_t>(timestamp));

    return enc.take();
}

Result<ContractResult> ContractResult::from_cbor(BytesView data)
{
    auto ctx_res = decode_context_value_bytes(data, kContentTypeContractResult);
    if (!ctx_res)
        return ctx_res.error();

    const auto& ctx = ctx_res.value();
    if (!ctx.is_map())
    {
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: expected map");
    }

    const auto& map = ctx.as_map();

    ContractResult result;

    auto it = map.find("status");
    if (it == map.end() || !it->second.is_int())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing or invalid status");
    result.status = static_cast<Status>(it->second.as_int());

    it = map.find("result");
    if (it == map.end())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing result");
    result.result = it->second;

    it = map.find("error_code");
    if (it == map.end() || !it->second.is_string())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing or invalid error_code");
    result.error_code = it->second.as_string();

    it = map.find("error_message");
    if (it == map.end() || !it->second.is_string())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing or invalid error_message");
    result.error_message = it->second.as_string();

    it = map.find("gas_used");
    if (it == map.end() || !it->second.is_int())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing or invalid gas_used");
    result.gas_used = it->second.as_int();

    it = map.find("timestamp");
    if (it == map.end() || !it->second.is_int())
        return SMO_ERR_PROTOCOL(712, Error, NoRetry, None, "ContractResult: missing or invalid timestamp");
    result.timestamp = it->second.as_int();

    return result;
}

// ── SchemaRegistry ────────────────────────────────────────────────────────

Result<void> SchemaRegistry::register_schema(const Schema& schema)
{
    if (schemas_.count(schema.name))
    {
        return SMO_ERR_PROTOCOL(720, Error, NoRetry, None, "Schema already registered: " + schema.name);
    }

    // Validate schema structure
    for (const auto& field : schema.fields)
    {
        if (field.name.empty())
        {
            return SMO_ERR_PROTOCOL(721, Error, NoRetry, None, "Schema field name cannot be empty");
        }
    }

    schemas_[schema.name] = schema;
    return {};
}

Result<void> SchemaRegistry::validate(const ContextValue& value, std::string_view schema_name) const
{
    auto it = schemas_.find(std::string(schema_name));
    if (it == schemas_.end())
    {
        return SMO_ERR_PROTOCOL(722, Error, NoRetry, None, "Schema not found: " + std::string(schema_name));
    }

    const auto& schema = it->second;

    if (!value.is_map())
    {
        return SMO_ERR_PROTOCOL(723, Error, NoRetry, None, "Value is not a map for schema validation");
    }

    const auto& map = value.as_map();

    // Check required fields
    for (const auto& field : schema.fields)
    {
        auto field_it = map.find(field.name);
        if (field_it == map.end())
        {
            if (field.required)
            {
                return SMO_ERR_PROTOCOL(724, Error, NoRetry, None,
                                        "Missing required field: " + field.name + " in schema " + schema.name);
            }
            continue;
        }

        // Check type
        if (field_it->second.type() != field.type)
        {
            return SMO_ERR_PROTOCOL(725, Error, NoRetry, None,
                                    "Type mismatch for field " + field.name + " in schema " + schema.name +
                                    ": expected " + std::to_string(static_cast<int>(field.type)) +
                                    ", got " + std::to_string(static_cast<int>(field_it->second.type())));
        }

        // If field is a map and has nested schema, validate recursively
        if (field.type == ContextValue::Type::Map)
        {
            auto nested_it = schema.nested_schemas.find(field.name);
            if (nested_it != schema.nested_schemas.end())
            {
                auto nested_res = validate(field_it->second, nested_it->first);
                if (!nested_res)
                    return nested_res.error();
            }
        }
    }

    return {};
}

bool SchemaRegistry::has_schema(std::string_view name) const
{
    return schemas_.count(std::string(name)) > 0;
}

std::optional<SchemaRegistry::Schema> SchemaRegistry::get_schema(std::string_view name) const
{
    auto it = schemas_.find(std::string(name));
    if (it == schemas_.end())
        return std::nullopt;
    return it->second;
}

std::vector<std::string> SchemaRegistry::list_schemas() const
{
    std::vector<std::string> names;
    names.reserve(schemas_.size());
    for (const auto& [name, _] : schemas_)
        names.push_back(name);
    return names;
}

SchemaRegistry& schema_registry()
{
    static SchemaRegistry reg;
    return reg;
}

} // namespace smo::cbor