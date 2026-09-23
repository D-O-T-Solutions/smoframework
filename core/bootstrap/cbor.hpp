#pragma once

// Minimal CBOR encoder/decoder (RFC 7049) for SMO Bootstrap Protocol.
// Supports: uint, bstr, tstr, array, map, nested maps.
// No floating point, no tagged values, no indefinite length.

#include "core/types.hpp"
#include "core/errors/error.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace smo::cbor {

    // ── Error codes ───────────────────────────────────────────────────────

    // Use Protocol category with codes 700-709 for CBOR errors

    // ── Encoder ───────────────────────────────────────────────────────────

    class Encoder
    {
    public:
        Encoder() = default;

        Bytes take() { return std::move(buf_); }

        void encode_uint(uint64_t val);
        void encode_int(int64_t val);
        void encode_bytes(BytesView data);
        void encode_string(const std::string& s);
        void encode_array(size_t count);
        void encode_map(size_t count);

        // Direct byte append (for content-type byte and special CBOR values)
        void push_byte(uint8_t b) { buf_.push_back(b); }
        void push_bytes(const uint8_t* data, size_t len) { buf_.insert(buf_.end(), data, data + len); }

        // Encoded size (for pre-allocation)
        size_t size() const { return buf_.size(); }

    private:
        void encode_head(uint8_t major, uint64_t val);
        Bytes buf_;
    };

    // ── Decoder ───────────────────────────────────────────────────────────

    class Decoder
    {
    public:
        explicit Decoder(BytesView data) : data_(data), pos_(0) {}

        bool done() const { return pos_ >= data_.size(); }
        size_t remaining() const { return data_.size() - pos_; }
        size_t offset() const { return pos_; }

        // Peek the next major type without consuming
        uint8_t peek_major() const;

        Result<uint64_t> decode_uint();
        Result<int64_t> decode_int();
        Result<BytesView> decode_bytes();
        Result<std::string> decode_string();
        Result<size_t> decode_array_size();
        Result<size_t> decode_map_size();

        // Skip one value entirely
        Result<void> skip();

        // Advance position (for content-type byte)
        void advance(size_t n) { pos_ += n; }

        // Get current position data view
        BytesView current_view() const { return data_.subspan(pos_); }

    private:
        Result<uint64_t> decode_head(uint8_t& major_out);

        BytesView data_;
        size_t pos_ = 0;
    };

    // ── Convenience helpers ───────────────────────────────────────────────

    // Map key-value writer — encodes a uint key followed by a value
    void encode_uint_key(Encoder& enc, uint64_t key);
    void encode_string_key(Encoder& enc, const std::string& key);

    // Find and decode a value by uint key in a CBOR map
    Result<uint64_t> decode_uint_field(Decoder& dec, uint64_t key);
    Result<std::string> decode_string_field(Decoder& dec, uint64_t key);
    Result<BytesView> decode_bytes_field(Decoder& dec, uint64_t key);

} // namespace smo::cbor
