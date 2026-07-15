#include "compiler/smir/smir.hpp"
#include <sstream>

namespace smo {

static const char* smir_opcode_name(SmirOpcode op) {
    switch (op) {
        case SmirOpcode::Nop:       return "nop";
        case SmirOpcode::Call:      return "call";
        case SmirOpcode::Load:      return "load";
        case SmirOpcode::Store:     return "store";
        case SmirOpcode::Cond:      return "cond";
        case SmirOpcode::Seq:       return "seq";
        case SmirOpcode::Parallel:  return "parallel";
        case SmirOpcode::BindInput: return "bind_input";
        case SmirOpcode::BindOutput:return "bind_output";
        case SmirOpcode::Literal:   return "literal";
        case SmirOpcode::Move:      return "move";
        case SmirOpcode::Assert:    return "assert";
        case SmirOpcode::Debug:     return "debug";
    }
    return "unknown";
}

static std::string operand_str(const SmirOperand& op) {
    switch (op.type) {
        case SmirOperand::Literal:    return "\"" + op.value + "\"";
        case SmirOperand::Identifier: return "%" + op.value;
        case SmirOperand::Temp:       return "$" + op.value;
        default:                      return "_";
    }
}

std::string SmirModule::to_string() const {
    std::ostringstream os;
    os << "; SMIR module: " << name << "\n";
    for (auto& [k, v] : metadata) {
        os << "; " << k << " = " << v << "\n";
    }
    for (auto& block : blocks) {
        os << "\n" << block.label << ":\n";
        for (auto& inst : block.instructions) {
            os << "  " << smir_opcode_name(inst.opcode);
            if (inst.dst.type != SmirOperand::None) {
                os << " " << operand_str(inst.dst);
            }
            if (inst.lhs.type != SmirOperand::None) {
                os << ", " << operand_str(inst.lhs);
            }
            if (inst.rhs.type != SmirOperand::None) {
                os << ", " << operand_str(inst.rhs);
            }
            if (!inst.annotation.empty()) {
                os << "  ; " << inst.annotation;
            }
            os << "\n";
        }
    }
    return os.str();
}

} // namespace smo
