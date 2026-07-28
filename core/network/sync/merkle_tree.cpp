#include "merkle_tree.hpp"
#include "sync_errors.hpp"
#include <core/crypto/hash_provider.hpp>
#include <cstring>

namespace smo::sync {

    MerkleTree::MerkleTree(TreeID tid) : id(tid)
    {
        uint32_t n = tree_bucket_count(tid);
        buckets.resize(n);
    }

    void MerkleTree::rebuild()
    {
        auto& hp = HashProvider::default_provider();
        for (auto& bucket : buckets)
        {
            if (!bucket.data.empty())
            {
                auto h = hp.hash(BytesView(bucket.data));
                std::memcpy(bucket.hash.data(), h.data(), std::min(h.size(), size_t(32)));
            }
            else
            {
                bucket.hash.fill(0);
                bucket.epoch = 0;
            }
        }

        Bytes all_hashes;
        all_hashes.reserve(buckets.size() * 32);
        for (const auto& b : buckets)
        {
            all_hashes.insert(all_hashes.end(), b.hash.begin(), b.hash.end());
        }
        auto root = hp.hash(BytesView(all_hashes));
        std::memcpy(root_hash.data(), root.data(), std::min(root.size(), size_t(32)));
    }

    bool MerkleTree::operator==(const MerkleTree& o) const
    {
        return id == o.id && epoch == o.epoch && version_vector == o.version_vector && root_hash == o.root_hash;
    }

    Bytes MerkleNode::serialize() const
    {
        Bytes out;
        out.insert(out.end(), hash.begin(), hash.end());
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&epoch), reinterpret_cast<const uint8_t*>(&epoch) + 8);
        uint32_t dlen = static_cast<uint32_t>(data.size());
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&dlen), reinterpret_cast<const uint8_t*>(&dlen) + 4);
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

    Result<MerkleNode> MerkleNode::deserialize(BytesView data)
    {
        size_t pos = 0;
        if (pos + 32 + 8 + 4 > data.size())
        {
            return Error(SyncErrc::Truncated, "MerkleNode: truncated");
        }
        MerkleNode n;
        std::memcpy(n.hash.data(), data.data() + pos, 32);
        pos += 32;
        std::memcpy(&n.epoch, data.data() + pos, 8);
        pos += 8;
        uint32_t dlen;
        std::memcpy(&dlen, data.data() + pos, 4);
        pos += 4;
        if (pos + dlen > data.size())
        {
            return Error(SyncErrc::Truncated, "MerkleNode: data truncated");
        }
        n.data.assign(data.data() + pos, data.data() + pos + dlen);
        return n;
    }

    Bytes MerkleTree::serialize() const
    {
        Bytes out;
        out.push_back(static_cast<uint8_t>(id));
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&epoch), reinterpret_cast<const uint8_t*>(&epoch) + 8);
        auto vv_bytes = version_vector.serialize();
        uint32_t vv_len = static_cast<uint32_t>(vv_bytes.size());
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&vv_len), reinterpret_cast<const uint8_t*>(&vv_len) + 4);
        out.insert(out.end(), vv_bytes.begin(), vv_bytes.end());
        out.insert(out.end(), root_hash.begin(), root_hash.end());
        uint32_t bcount = static_cast<uint32_t>(buckets.size());
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&bcount), reinterpret_cast<const uint8_t*>(&bcount) + 4);
        for (const auto& b : buckets)
        {
            auto bbytes = b.serialize();
            out.insert(out.end(), bbytes.begin(), bbytes.end());
        }
        return out;
    }

    Result<MerkleTree> MerkleTree::deserialize(BytesView data)
    {
        size_t pos = 0;
        if (pos + 1 + 8 + 4 > data.size())
        {
            return Error(SyncErrc::Truncated, "MerkleTree: truncated header");
        }
        MerkleTree t;
        t.id = static_cast<TreeID>(data[pos]);
        pos += 1;
        std::memcpy(&t.epoch, data.data() + pos, 8);
        pos += 8;
        uint32_t vv_len;
        std::memcpy(&vv_len, data.data() + pos, 4);
        pos += 4;
        if (pos + vv_len > data.size())
        {
            return Error(SyncErrc::Truncated, "MerkleTree: version_vector truncated");
        }
        auto vv_r = VersionVector::deserialize(BytesView(data.data() + pos, vv_len));
        if (!vv_r)
            return vv_r.error();
        t.version_vector = std::move(vv_r.value());
        pos += vv_len;
        if (pos + 32 + 4 > data.size())
        {
            return Error(SyncErrc::Truncated, "MerkleTree: root_hash truncated");
        }
        std::memcpy(t.root_hash.data(), data.data() + pos, 32);
        pos += 32;
        uint32_t bcount;
        std::memcpy(&bcount, data.data() + pos, 4);
        pos += 4;
        for (uint32_t i = 0; i < bcount; ++i)
        {
            auto br = MerkleNode::deserialize(BytesView(data.data() + pos, data.size() - pos));
            if (!br)
                return br.error();
            t.buckets.push_back(std::move(br.value()));
            pos += 32 + 8 + 4 + br.value().data.size();
        }
        return t;
    }

} // namespace smo::sync