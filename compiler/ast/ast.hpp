#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "core/opcode/opcode.h"

namespace smo {

enum class AstNodeType : uint8_t {
    Contract,
    OpcodeCall,
    Parameter,
    Condition,
    Sequence,
    Parallel,
    InputBinding,
    OutputBinding,
    Literal,
    Identifier
};

struct AstNode {
    AstNodeType type;
    std::string value;
    std::vector<std::unique_ptr<AstNode>> children;
    std::map<std::string, std::string> attributes;
};

struct ContractAst {
    std::string contract_id;
    std::string category;
    std::string opcode;
    std::string name;
    std::string semver;
    std::vector<std::unique_ptr<AstNode>> body;

    static std::unique_ptr<AstNode> make_node(AstNodeType type, std::string val = "");
};

} // namespace smo
