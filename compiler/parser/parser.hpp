#pragma once

#include "compiler/ast/ast.hpp"
#include "core/contract/contract_definition.hpp"
#include "core/errors/error.hpp"

namespace smo {

class Parser {
public:
    Result<ContractAst> parse(const ContractDefinition& def);
};

} // namespace smo
