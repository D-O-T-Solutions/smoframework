#include "compiler/compiler.h"
#include "compiler/ast/ast.hpp"
#include "compiler/parser/parser.hpp"
#include "compiler/planner/planner.hpp"
#include "compiler/graph/builder.hpp"
#include "compiler/optimizer/optimizer.hpp"
#include "compiler/validator/semantic.hpp"
#include "compiler/validator/final.hpp"
#include "compiler/smir/smir.hpp"
#include "core/crypto/hash_provider.hpp"

namespace smo {

class CompilerImpl : public Compiler {
public:
    Compiler::Result compile(const Intent& intent, std::error_code& ec) override {
        ec.clear();

        ContractDefinition def;
        def.contract_version = "1.0";
        def.category = "native";
        def.opcode = opcode_name(intent.opcode);
        def.name = def.opcode;
        def.semver = "1.0.0";
        def.contract_id = ContractID::compute(intent.parameters_json.empty()
        ? "{\"opcode\":\"" + def.opcode + "\"}"
        : intent.parameters_json);

        Parser parser;
        auto ast_result = parser.parse(def);
        if (!ast_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }
        auto ast = std::move(*ast_result);

        SmirModule smir;
        smir.name = def.opcode;
        SmirBasicBlock entry;
        entry.label = "entry";
        SmirInstruction call;
        call.opcode = SmirOpcode::Call;
        call.lhs = SmirOperand{SmirOperand::Identifier, def.opcode};
        call.annotation = def.name;
        entry.instructions.push_back(std::move(call));
        smir.blocks.push_back(std::move(entry));

        SemanticValidator sem_val;
        auto sem_result = sem_val.validate(smir, ast);
        if (!sem_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }
        smir = std::move(*sem_result);

        Planner planner;
        auto plan_result = planner.plan(smir, def.contract_id.to_string());
        if (!plan_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }

        GraphBuilder builder;
        auto dag_result = builder.build(*plan_result);
        if (!dag_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }

        Optimizer optimizer;
        auto opt_result = optimizer.optimize(*dag_result);
        if (!opt_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }

        FinalValidator fin_val;
        FinalValidator::Config fin_cfg;
        auto fin_result = fin_val.validate(*opt_result, fin_cfg);
        if (!fin_result) {
            ec = std::make_error_code(std::errc::invalid_argument);
            return {ExecutionGraph{}, ""};
        }

        auto& hp = HashProvider::default_provider();
        auto serialized = std::to_string(fin_result->nodes.size());
        Compiler::Result result;
        result.graph = std::move(*fin_result);
        result.graph_hash = hp.hash_hex(serialized);
        return result;
    }

private:
    static std::string opcode_name(Opcode op) {
        switch (op) {
            case Opcode::LS:         return "ls";
            case Opcode::PUT:        return "put";
            case Opcode::GET:        return "get";
            case Opcode::EXEC:       return "exec";
            case Opcode::QUARANTINE: return "quarantine";
            default:                 return "custom";
        }
    }
};

std::unique_ptr<Compiler> Compiler::create() {
    return std::make_unique<CompilerImpl>();
}

} // namespace smo
