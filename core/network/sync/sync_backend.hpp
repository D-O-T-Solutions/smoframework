#pragma once

#include "merkle_tree.hpp"
#include "sync_errors.hpp"
#include <core/types.hpp>
#include <cstdint>

namespace smo::sync {

struct Delta {
    TreeID      tree_id;
    uint64_t    base_epoch = 0;
    Bytes       data;

    uint32_t entry_count = 0;
    bool     is_snapshot = false;

    Bytes serialize() const;
    static Result<Delta> deserialize(BytesView data);
};

struct SyncBackend {
    virtual ~SyncBackend() = default;

    virtual Delta get_membership_delta(const VersionVector& vv) = 0;
    virtual Delta get_crl_delta(const VersionVector& vv) = 0;
    virtual Delta get_policy_delta(const VersionVector& vv) = 0;
    virtual Delta get_contract_delta(const VersionVector& vv) = 0;

    virtual Delta get_full_snapshot(TreeID id) = 0;

    virtual MerkleTree compute_tree(TreeID id) = 0;
};

} // namespace smo::sync