#include "compiler/parser/parser.hpp"
#include "core/crypto/hash_provider.hpp"
#include <sstream>

namespace smo {

Result<ContractAst> Parser::parse(const ContractDefinition& def) {
    ContractAst ast;
    ast.contract_id = def.contract_id.hex;
    ast.category    = def.category;
    ast.opcode      = def.opcode;
    ast.name        = def.name;
    ast.semver      = def.semver;

    auto opcode_node = ContractAst::make_node(AstNodeType::OpcodeCall, def.opcode);
    for (auto& param : def.parameters) {
        auto pnode = ContractAst::make_node(AstNodeType::Parameter, param.name);
        pnode->attributes["type"] = param.type;
        pnode->attributes["required"] = param.required ? "true" : "false";
        if (param.default_value) {
            pnode->attributes["default"] = *param.default_value;
        }
        opcode_node->children.push_back(std::move(pnode));
    }

    auto seq = ContractAst::make_node(AstNodeType::Sequence);
    seq->children.push_back(std::move(opcode_node));
    ast.body.push_back(std::move(seq));

    return ast;
}

} // namespace smo
