#include "selector.hpp"
#include "../trust/trust.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <random>
#include <sstream>
#include <unordered_set>

namespace smo {
namespace select {

// ===========================================================================
// Helpers
// ===========================================================================
namespace {

bool matches_tags(const PeerRecord& rec, const std::vector<std::string>& required) {
    if (required.empty()) return true;
    std::unordered_set<std::string> tag_set(rec.tags.begin(), rec.tags.end());
    for (const auto& t : required) {
        if (tag_set.find(t) == tag_set.end()) return false;
    }
    return true;
}

bool matches_version(const std::string& version, const std::string& constraint) {
    // Simplified semver matching: prefix operators.
    if (constraint.empty()) return true;
    if (constraint[0] == '<') {
        auto cmp = constraint.substr(1);
        return version < cmp;
    }
    if (constraint[0] == '>') {
        auto cmp = constraint.substr(1);
        return version > cmp;
    }
    if (constraint[0] == '=' && constraint.size() > 1) {
        auto cmp = constraint.substr(1);
        return version == cmp;
    }
    // No prefix: exact match
    return version == constraint;
}

// Tokenizer for expression language
enum class TokenType {
    Ident, Str, Number, Eq, Neq, Lt, Gt, Le, Ge,
    And, Or, Not, LParen, RParen, Eof
};

struct Token {
    TokenType type;
    std::string value;
};

class Lexer {
public:
    explicit Lexer(std::string_view src) : src_(src), pos_(0) {}

    Token peek() {
        if (lookahead_.type != TokenType::Eof) return lookahead_;
        lookahead_ = advance();
        return lookahead_;
    }

    Token consume() {
        auto t = lookahead_.type != TokenType::Eof ? lookahead_ : advance();
        lookahead_ = Token{TokenType::Eof, ""};
        return t;
    }

private:
    std::string_view src_;
    size_t pos_ = 0;
    Token lookahead_{TokenType::Eof, ""};

    Token advance() {
        skip_whitespace();
        if (pos_ >= src_.size()) return {TokenType::Eof, ""};

        char c = src_[pos_];
        if (c == '"') return scan_string();
        if (c == '(') { pos_++; return {TokenType::LParen, "("}; }
        if (c == ')') { pos_++; return {TokenType::RParen, ")"}; }
        if (c == '=' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; return {TokenType::Eq, "=="}; }
        if (c == '!' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; return {TokenType::Neq, "!="}; }
        if (c == '>') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; return {TokenType::Ge, ">="}; }
            pos_++; return {TokenType::Gt, ">"};
        }
        if (c == '<') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; return {TokenType::Le, "<="}; }
            pos_++; return {TokenType::Lt, "<"};
        }
        if (c == '&' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '&') { pos_ += 2; return {TokenType::And, "&&"}; }
        if (c == '|' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '|') { pos_ += 2; return {TokenType::Or, "||"}; }
        if (c == '!') { pos_++; return {TokenType::Not, "!"}; }

        // Identifiers
        if (std::isalpha(c) || c == '_') {
            size_t start = pos_;
            while (pos_ < src_.size() && (std::isalnum(src_[pos_]) || src_[pos_] == '_' || src_[pos_] == '.')) pos_++;
            return {TokenType::Ident, std::string(src_.substr(start, pos_ - start))};
        }

        // Numbers
        if (std::isdigit(c) || c == '.') {
            size_t start = pos_;
            while (pos_ < src_.size() && (std::isdigit(src_[pos_]) || src_[pos_] == '.')) pos_++;
            return {TokenType::Number, std::string(src_.substr(start, pos_ - start))};
        }

        pos_++;
        return {TokenType::Eof, ""};
    }

    void skip_whitespace() {
        while (pos_ < src_.size() && (src_[pos_] == ' ' || src_[pos_] == '\t' || src_[pos_] == '\n')) pos_++;
    }

    Token scan_string() {
        pos_++; // skip opening "
        size_t start = pos_;
        while (pos_ < src_.size() && src_[pos_] != '"') pos_++;
        std::string val(src_.substr(start, pos_ - start));
        if (pos_ < src_.size()) pos_++; // skip closing "
        return {TokenType::Str, val};
    }
};

class EvalContext {
public:
    const PeerRecord& rec;
    double trust = 0.0;

    std::string get_field(const std::string& name) const {
        if (name == "role") {
            return to_string(rec.role);
        }
        if (name == "trust") {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.4f", trust);
            return buf;
        }
        if (name == "arch") return rec.arch;
        if (name == "os" || name == "platform") return rec.platform;
        if (name == "version") return rec.version;
        if (name == "mesh") return rec.mesh_name;
        if (name == "name") return rec.display_name;
        if (name == "state") return to_string(rec.state);
        if (name == "location") return rec.location;
        if (name == "hostname") return rec.hostname;
        return "";
    }

    bool tags_contain(const std::string& tag) const {
        for (auto& t : rec.tags) {
            if (t == tag) return true;
        }
        return false;
    }
};

// Recursive-descent expression parser
class ExprParser {
public:
    explicit ExprParser(Lexer& lex) : lex_(lex) {}

    bool parse(const EvalContext& ctx) {
        return or_expr(ctx);
    }

private:
    Lexer& lex_;

    bool or_expr(const EvalContext& ctx) {
        bool left = and_expr(ctx);
        while (lex_.peek().type == TokenType::Or) {
            lex_.consume();
            left = left || and_expr(ctx);
        }
        return left;
    }

    bool and_expr(const EvalContext& ctx) {
        bool left = primary(ctx);
        while (lex_.peek().type == TokenType::And) {
            lex_.consume();
            left = left && primary(ctx);
        }
        return left;
    }

    bool primary(const EvalContext& ctx) {
        auto tok = lex_.peek();

        if (tok.type == TokenType::Not) {
            lex_.consume();
            return !primary(ctx);
        }

        if (tok.type == TokenType::LParen) {
            lex_.consume();
            bool val = or_expr(ctx);
            lex_.consume(); // RParen
            return val;
        }

        // field OP value
        if (tok.type == TokenType::Ident) {
            auto field = lex_.consume();

            // Special: "tag" — check if tags contain value
            if (field.value == "tag" || field.value == "tags") {
                if (lex_.peek().type == TokenType::Eq || lex_.peek().type == TokenType::Neq) {
                    auto op = lex_.consume();
                    auto val = lex_.consume();
                    bool has = ctx.tags_contain(val.value);
                    return op.type == TokenType::Eq ? has : !has;
                }
                return false;
            }

            auto op = lex_.consume();
            auto val = lex_.consume();

            if (op.type != TokenType::Eq && op.type != TokenType::Neq &&
                op.type != TokenType::Gt && op.type != TokenType::Lt &&
                op.type != TokenType::Ge && op.type != TokenType::Le) {
                return false;
            }

            std::string fval = ctx.get_field(field.value);

            int cmp = fval.compare(val.value);
            if (op.type == TokenType::Eq) return cmp == 0;
            if (op.type == TokenType::Neq) return cmp != 0;

            // Numeric comparisons for trust
            if (field.value == "trust") {
                double fnum = std::strtod(fval.c_str(), nullptr);
                double vnum = std::strtod(val.value.c_str(), nullptr);
                if (op.type == TokenType::Gt) return fnum > vnum;
                if (op.type == TokenType::Lt) return fnum < vnum;
                if (op.type == TokenType::Ge) return fnum >= vnum;
                if (op.type == TokenType::Le) return fnum <= vnum;
            }

            // String comparisons for other fields
            if (op.type == TokenType::Gt) return fval > val.value;
            if (op.type == TokenType::Lt) return fval < val.value;
            if (op.type == TokenType::Ge) return fval >= val.value;
            if (op.type == TokenType::Le) return fval <= val.value;

            return false;
        }

        // bare "online" / "offline" as boolean state check
        if (tok.type == TokenType::Ident) {
            auto id = lex_.consume().value;
            std::string st = to_string(ctx.rec.state);
            // lowercase comparison
            for (auto& c : st) c = static_cast<char>(std::tolower(c));
            return id == st;
        }

        return false;
    }
};

bool evaluate_expression(const PeerRecord& rec, double trust,
                          const std::string& expr) {
    Lexer lex(expr);
    EvalContext ctx{rec, trust};
    ExprParser parser(lex);
    return parser.parse(ctx);
}

// Compute a composite score for ranking
double composite_score(const PeerRecord& rec, double trust_score) {
    double trust_w = trust_score;
    double rtt_w = rec.rtt_ms > 0 ? 1.0 / (1.0 + rec.rtt_ms / 1000.0) : 0.5;
    double online_w = rec.state == PeerState::Online ? 1.0 : 0.0;
    return 0.5 * trust_w + 0.3 * rtt_w + 0.2 * online_w;
}

struct ScoredPeer {
    const PeerRecord* rec;
    double trust;
    double score;
};

} // anonymous namespace

// ===========================================================================
// NodeSet::pick_one
// ===========================================================================
NodeID NodeSet::pick_one() const noexcept {
    if (entries.empty()) return NodeID{};
    // Pick highest trust, then lowest RTT
    const Entry* best = &entries[0];
    for (const auto& e : entries) {
        if (e.trust_score > best->trust_score) {
            best = &e;
        } else if (e.trust_score == best->trust_score && e.rtt_ms < best->rtt_ms) {
            best = &e;
        }
    }
    return best->id;
}

// ===========================================================================
// Selector::select
// ===========================================================================
Result<NodeSet> Selector::select(const SelectQuery& query) const {
    // Validate: at least one filter must be set
    if (!query.node_id && !query.name && !query.role && query.tags.empty() &&
        !query.cap_mask && !query.trust_min && !query.trust_max &&
        !query.os && !query.arch && !query.version_constraint &&
        !query.mesh_name && !query.where_expr && !query.state) {
        return SMO_ERR(Discovery, 450, Info, NoRetry, None,
                              "empty selection query — no filter specified");
    }

    auto peers = table_.peers();
    if (peers.empty()) {
        return SMO_ERR(Discovery, 451, Info, RetrySafe, None,
                              "no nodes in membership table");
    }

    std::vector<ScoredPeer> candidates;
    candidates.reserve(peers.size());

    for (const auto& rec : peers) {
        // NodeID exact match
        if (query.node_id && rec.node_id != query.node_id.value())
            continue;

        // Name match (display_name or alias)
        if (query.name) {
            bool name_match = (rec.display_name == query.name.value());
            if (!name_match) {
                for (const auto& a : rec.aliases) {
                    if (a == query.name.value()) { name_match = true; break; }
                }
            }
            if (!name_match) continue;
        }

        // Role match
        if (query.role && rec.role != query.role.value())
            continue;

        // Tags match (all required tags must be present)
        if (!matches_tags(rec, query.tags)) continue;

        // OS match
        if (query.os && rec.platform != query.os.value()) continue;

        // Arch match
        if (query.arch && rec.arch != query.arch.value()) continue;

        // Version constraint
        if (query.version_constraint && !matches_version(rec.version, query.version_constraint.value())) continue;

        // Mesh name match
        if (query.mesh_name && rec.mesh_name != query.mesh_name.value()) continue;

        // State match
        if (query.state && rec.state != query.state.value()) continue;

        // Capability filter (future: check against capability registry)
        if (query.cap_mask) continue; // not yet implemented

        // Trust score — need to query trust store
        double trust_score = 0.5; // default

        // Trust range
        if (query.trust_min && trust_score < query.trust_min.value())
            continue;
        if (query.trust_max && trust_score > query.trust_max.value())
            continue;

        // Expression
        if (query.where_expr && !evaluate_expression(rec, trust_score, query.where_expr.value()))
            continue;

        // Compute composite score for ranking
        double score = composite_score(rec, trust_score);

        candidates.push_back({&rec, trust_score, score});
    }

    if (candidates.empty()) {
        return SMO_ERR(Discovery, 451, Info, RetrySafe, None,
                              "no nodes match selection criteria");
    }

    // Sort by composite score descending
    std::sort(candidates.begin(), candidates.end(),
              [](const ScoredPeer& a, const ScoredPeer& b) {
                  return a.score > b.score;
              });

    // Apply mode
    NodeSet result;
    result.entries.reserve(candidates.size());

    auto add_entry = [&](const ScoredPeer& sp) {
        NodeSet::Entry e;
        e.id = sp.rec->node_id;
        e.display_name = sp.rec->display_name;
        e.role = sp.rec->role;
        e.tags = sp.rec->tags;
        e.trust_score = sp.trust;
        e.rtt_ms = sp.rec->rtt_ms;
        e.os = sp.rec->platform;
        e.arch = sp.rec->arch;
        e.version = sp.rec->version;
        result.entries.push_back(std::move(e));
    };

    switch (query.mode) {
    case SelectMode::ALL:
        for (const auto& sp : candidates) add_entry(sp);
        break;

    case SelectMode::NEAREST:
        // Already sorted by score; pick the first
        if (!candidates.empty()) add_entry(candidates[0]);
        break;

    case SelectMode::TOP_N: {
        int n = query.limit > 0 ? query.limit : static_cast<int>(candidates.size());
        for (int i = 0; i < n && i < static_cast<int>(candidates.size()); ++i)
            add_entry(candidates[i]);
        break;
    }

    case SelectMode::RANDOM: {
        int n = query.limit > 0 ? query.limit : 1;
        if (n >= static_cast<int>(candidates.size())) {
            for (const auto& sp : candidates) add_entry(sp);
        } else {
            std::mt19937_64 rng(
                static_cast<uint64_t>(std::time(nullptr)));
            std::shuffle(candidates.begin(), candidates.end(), rng);
            for (int i = 0; i < n; ++i) add_entry(candidates[i]);
        }
        break;
    }
    }

    return result;
}

} // namespace select
} // namespace smo
