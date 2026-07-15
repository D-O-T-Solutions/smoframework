#include "compiler/ast/ast.hpp"

namespace smo {

std::unique_ptr<AstNode> ContractAst::make_node(AstNodeType type, std::string val) {
    auto node = std::make_unique<AstNode>();
    node->type = type;
    node->value = std::move(val);
    return node;
}

} // namespace smo
