#include "compiler/validator/semantic.hpp"

namespace smo {

Result<SmirModule> SemanticValidator::validate(const SmirModule& module, const ContractAst& ast) {
    (void)ast;

    if (module.blocks.empty()) {
        return SMO_ERR_COMPILER(1, Error, NoRetry, None,
            "SMIR module has no basic blocks");
    }

    for (auto& block : module.blocks) {
        if (block.label.empty()) {
            return SMO_ERR_COMPILER(2, Error, NoRetry, None,
                "Basic block with empty label");
        }
        for (auto& inst : block.instructions) {
            if (inst.opcode == SmirOpcode::Call && inst.lhs.type == SmirOperand::None) {
                return SMO_ERR_COMPILER(3, Error, NoRetry, None,
                    "call instruction with no target");
            }
        }
    }

    return module;
}

} // namespace smo
