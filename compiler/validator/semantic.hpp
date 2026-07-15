#pragma once

#include "compiler/ast/ast.hpp"
#include "compiler/smir/smir.hpp"
#include "core/errors/error.hpp"

namespace smo {

class SemanticValidator {
public:
    Result<SmirModule> validate(const SmirModule& module, const ContractAst& ast);
};

} // namespace smo
