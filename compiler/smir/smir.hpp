#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "core/errors/error.hpp"
#include "core/types.hpp"

namespace smo {

enum class SmirOpcode : uint8_t {
    Nop        = 0x00,
    Call       = 0x01,
    Load       = 0x02,
    Store      = 0x03,
    Cond       = 0x04,
    Seq        = 0x05,
    Parallel   = 0x06,
    BindInput  = 0x07,
    BindOutput = 0x08,
    Literal    = 0x09,
    Move       = 0x0A,
    Assert     = 0x0B,
    Debug      = 0x0C,
};

struct SmirOperand {
    enum Type : uint8_t { None, Literal, Identifier, Temp };
    Type   type{None};
    std::string value;
};

struct SmirInstruction {
    SmirOpcode      opcode{SmirOpcode::Nop};
    SmirOperand     dst;
    SmirOperand     lhs;
    SmirOperand     rhs;
    std::string     annotation;
};

struct SmirBasicBlock {
    std::string                  label;
    std::vector<SmirInstruction> instructions;
};

struct SmirModule {
    std::string                  name;
    std::vector<SmirBasicBlock>  blocks;
    std::map<std::string, std::string> metadata;

    std::string to_string() const;
};

} // namespace smo
