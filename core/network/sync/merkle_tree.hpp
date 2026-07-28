#pragma once

#include "version_vector.hpp"
#include <core/types.hpp>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace smo::sync {

    enum class TreeID : uint8_t
    {
        Membership = 0,
        CRL = 1,
        Policy = 2,
        Contract = 3,
    };

    inline const char* tree_name(TreeID id)
    {
        switch (id)
        {
        case TreeID::Membership:
            return "membership";
        case TreeID::CRL:
            return "crl";
        case TreeID::Policy:
            return "policy";
        case TreeID::Contract:
            return "contract";
        }
        return "unknown";
    }

    inline uint32_t tree_bucket_count(TreeID id)
    {
        switch (id)
        {
        case TreeID::Membership:
            return 256;
        case TreeID::CRL:
            return 256;
        case TreeID::Policy:
            return 64;
        case TreeID::Contract:
            return 64;
        }
        return 0;
    }

    struct MerkleNode
    {
        std::array<uint8_t, 32> hash{};
        uint64_t epoch = 0;
        Bytes data;

        Bytes serialize() const;
        static Result<MerkleNode> deserialize(BytesView data);
    };

    struct MerkleTree
    {
        TreeID id;
        uint64_t epoch = 0;
        VersionVector version_vector;
        std::array<uint8_t, 32> root_hash{};

        std::vector<MerkleNode> buckets;

        MerkleTree() = default;
        explicit MerkleTree(TreeID tid);

        void rebuild();
        bool operator==(const MerkleTree& o) const;
        bool operator!=(const MerkleTree& o) const { return !(*this == o); }

        Bytes serialize() const;
        static Result<MerkleTree> deserialize(BytesView data);
    };

} // namespace smo::sync