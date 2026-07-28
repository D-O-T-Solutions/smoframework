#include "raft_log.hpp"
#include <algorithm>
#include <mutex>

namespace smo::consensus {

    Result<uint64_t> InMemoryRaftLog::append(const RaftLogEntry& entry)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        RaftLogEntry e = entry;
        if (entries_.empty())
        {
            e.index = 1;
        }
        else
        {
            e.index = entries_.back().index + 1;
        }
        entries_.push_back(std::move(e));
        return entries_.back().index;
    }

    Result<RaftLogEntry> InMemoryRaftLog::get(uint64_t index) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& e : entries_)
        {
            if (e.index == index)
                return e;
        }
        return SMO_ERR(Internal, 100, Critical, NoRetry, ManualIntervention,
                       "RaftLog: entry not found at index " + std::to_string(index));
    }

    Result<void> InMemoryRaftLog::truncate(uint64_t from_index)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::remove_if(entries_.begin(), entries_.end(),
                                 [from_index](const RaftLogEntry& e) { return e.index >= from_index; });
        entries_.erase(it, entries_.end());
        return {};
    }

    Result<std::vector<RaftLogEntry>> InMemoryRaftLog::range(uint64_t start, uint64_t end) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<RaftLogEntry> result;
        for (const auto& e : entries_)
        {
            if (e.index >= start && e.index <= end)
            {
                result.push_back(e);
            }
        }
        return result;
    }

} // namespace smo::consensus