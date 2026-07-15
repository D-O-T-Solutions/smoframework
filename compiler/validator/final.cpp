#include "compiler/validator/final.hpp"
#include <algorithm>
#include <map>
#include <queue>
#include <set>

namespace smo {

static bool has_cycle(const ExecutionGraph& graph) {
    std::map<std::string, std::vector<std::string>> adj;
    std::map<std::string, int> in_degree;

    for (auto& node : graph.nodes) {
        if (adj.find(node.task_id) == adj.end())
            adj[node.task_id] = {};
        if (in_degree.find(node.task_id) == in_degree.end())
            in_degree[node.task_id] = 0;
    }

    for (auto& node : graph.nodes) {
        for (auto& dep : node.depends_on) {
            adj[dep].push_back(node.task_id);
            in_degree[node.task_id]++;
        }
    }

    std::queue<std::string> q;
    for (auto& [id, deg] : in_degree) {
        if (deg == 0) q.push(id);
    }

    size_t visited = 0;
    while (!q.empty()) {
        auto u = q.front(); q.pop();
        visited++;
        for (auto& v : adj[u]) {
            if (--in_degree[v] == 0) q.push(v);
        }
    }

    return visited != adj.size();
}

static uint32_t max_depth_dfs(
    const std::string& node_id,
    const std::map<std::string, std::vector<std::string>>& adj,
    std::map<std::string, uint32_t>& memo)
{
    auto it = memo.find(node_id);
    if (it != memo.end()) return it->second;

    uint32_t depth = 0;
    auto adj_it = adj.find(node_id);
    if (adj_it != adj.end()) {
        for (auto& child : adj_it->second) {
            depth = std::max(depth, 1 + max_depth_dfs(child, adj, memo));
        }
    }
    memo[node_id] = depth;
    return depth;
}

Result<ExecutionGraph> FinalValidator::validate(
    const ExecutionGraph& graph, const Config& cfg)
{
    if (graph.nodes.empty()) {
        return SMO_ERR_COMPILER(10, Error, NoRetry, None,
            "DAG has no nodes");
    }

    if (graph.nodes.size() > cfg.max_nodes) {
        return SMO_ERR_COMPILER(11, Error, NoRetry, None,
            "DAG exceeds max nodes");
    }

    if (cfg.reject_cycles && has_cycle(graph)) {
        return SMO_ERR_COMPILER(12, Error, NoRetry, None,
            "DAG contains a cycle");
    }

    std::map<std::string, std::vector<std::string>> adj;
    for (auto& node : graph.nodes) {
        if (adj.find(node.task_id) == adj.end())
            adj[node.task_id] = {};
    }
    for (auto& node : graph.nodes) {
        for (auto& dep : node.depends_on) {
            adj[dep].push_back(node.task_id);
        }
    }

    std::map<std::string, uint32_t> memo;
    for (auto& node : graph.nodes) {
        uint32_t depth = max_depth_dfs(node.task_id, adj, memo);
        if (depth > cfg.max_depth) {
            return SMO_ERR_COMPILER(13, Error, NoRetry, None,
                "DAG exceeds max depth");
        }
    }

    return graph;
}

} // namespace smo
