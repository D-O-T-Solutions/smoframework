#pragma once

#include "selector.hpp"
#include <string>
#include <string_view>

namespace smo {
namespace select {

// Parse a --where expression string into a SelectQuery filter.
// This is a thin wrapper around the expression evaluator in selector.cpp.
// Returns error if the expression is syntactically invalid.
Result<void> validate_expression(std::string_view expr);

// Convert CLI flag values to a SelectQuery
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
    SelectMode mode = SelectMode::ALL,
    int limit = 0);

} // namespace select
} // namespace smo
