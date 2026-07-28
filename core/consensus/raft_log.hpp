#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace smo::consensus {

enum class RaftRole : uint8_t {
    Follower  = 0,
    Candidate = 1,
    Leader    = 2,
};

struct RaftLogEntry {
    uint64_t term = 0;
    uint64_t index = 0;
    Bytes    data;
    bool     is_noop = false;
};

struct RaftState {
    RaftRole role = RaftRole::Follower;
    uint64_t current_term = 0;
    uint64_t commit_index = 0;
    uint64_t last_applied = 0;
    std::string leader_id;
    uint64_t log_size = 0;
};

struct RaftConfig {
    std::string node_id;
    std::vector<std::string> peer_ids;
    uint64_t heartbeat_interval_ms = 100;
    uint64_t election_timeout_min_ms = 300;
    uint64_t election_timeout_max_ms = 500;
    uint64_t max_log_entries_per_append = 100;
};

class RaftLog {
public:
    virtual ~RaftLog() = default;

    virtual Result<uint64_t> append(const RaftLogEntry& entry) = 0;
    virtual Result<RaftLogEntry> get(uint64_t index) const = 0;
    virtual Result<void> truncate(uint64_t from_index) = 0;
    virtual Result<std::vector<RaftLogEntry>> range(uint64_t start, uint64_t end) const = 0;
    virtual uint64_t last_index() const noexcept = 0;
    virtual uint64_t last_term() const noexcept = 0;
    virtual uint64_t size() const noexcept = 0;
};

class RaftEngine {
public:
    virtual ~RaftEngine() = default;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual RaftState state() const = 0;

    virtual Result<uint64_t> propose(const Bytes& data) = 0;
    virtual Result<Bytes> read_quorum(const std::string& key) = 0;

    using CommitCallback = std::function<void(uint64_t index, const Bytes& data)>;
    virtual void on_commit(CommitCallback cb) = 0;
};

class InMemoryRaftLog : public RaftLog {
public:
    Result<uint64_t> append(const RaftLogEntry& entry) override;
    Result<RaftLogEntry> get(uint64_t index) const override;
    Result<void> truncate(uint64_t from_index) override;
    Result<std::vector<RaftLogEntry>> range(uint64_t start, uint64_t end) const override;
    uint64_t last_index() const noexcept override { return entries_.empty() ? 0 : entries_.back().index; }
    uint64_t last_term() const noexcept override { return entries_.empty() ? 0 : entries_.back().term; }
    uint64_t size() const noexcept override { return entries_.size(); }

private:
    std::vector<RaftLogEntry> entries_;
    mutable std::mutex mutex_;
};

} // namespace smo::consensus