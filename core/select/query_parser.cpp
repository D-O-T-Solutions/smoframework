#include "query_parser.hpp"

namespace smo {
namespace select {

Result<void> validate_expression(std::string_view expr) {
    if (expr.empty()) return {};
    // Use the expression parser to validate syntax
    // (Leverage the anonymous Lexer/ExprParser from selector.cpp indirectly
    //  by checking for basic well-formedness)
    bool has_paren = false;
    int paren_depth = 0;
    bool expect_field = true;
    for (size_t i = 0; i < expr.size(); ++i) {
        char c = expr[i];
        if (c == '(') { paren_depth++; has_paren = true; expect_field = true; }
        else if (c == ')') { paren_depth--; if (paren_depth < 0)
            return SMO_ERR(Discovery, 452, Warn, NoRetry, None,
                           "unbalanced parentheses in expression"); }
        else if (c == '"') {
            // Skip quoted string
            i++;
            while (i < expr.size() && expr[i] != '"') i++;
            if (i >= expr.size())
                return SMO_ERR(Discovery, 452, Warn, NoRetry, None,
                               "unterminated string in expression");
            expect_field = false;
        }
    }
    if (paren_depth != 0)
        return SMO_ERR(Discovery, 452, Warn, NoRetry, None,
                       "unbalanced parentheses in expression");
    return {};
}

SelectQuery query_from_cli(
    std::optional<std::string> name,
    std::optional<NodeID> node_id,
    std::optional<Role> role,
    std::vector<std::string> tags,
    std::optional<std::string> os,
    std::optional<std::string> arch,
    std::optional<std::string> version_constraint,
    std::optional<double> trust_min,
    std::optional<double> trust_max,
    std::optional<std::string> mesh_name,
    std::optional<std::string> where_expr,
    SelectMode mode,
    int limit)
{
    SelectQuery q;
    q.name = std::move(name);
    q.node_id = std::move(node_id);
    q.role = std::move(role);
    q.tags = std::move(tags);
    q.os = std::move(os);
    q.arch = std::move(arch);
    q.version_constraint = std::move(version_constraint);
    q.trust_min = std::move(trust_min);
    q.trust_max = std::move(trust_max);
    q.mesh_name = std::move(mesh_name);
    q.where_expr = std::move(where_expr);
    q.mode = mode;
    q.limit = limit;
    return q;
}

} // namespace select
} // namespace smo
