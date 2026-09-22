#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <core/types.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/discovery/gossip.hpp>
#include <core/network/sync/merkle_tree.hpp>
#include <core/identity/identity.hpp>
#include <fmt/core.h>

using namespace smo;

TEST_CASE("Benchmark validation - TCP transport creation", "[benchmark][tcp]")
{
    transport::TcpTransport transport;
    transport.configure({.local_port = 0, .remote_port = 8080});

    REQUIRE(transport.local_port() == 0);
    REQUIRE(transport.remote_port() == 8080);
}

TEST_CASE("Benchmark validation - Gossip engine creation", "[benchmark][gossip]")
{
    MembershipTable table;
    GossipEngine::Config cfg;
    cfg.fanout = 3;
    cfg.interval_ms = 100;

    GossipEngine engine(table, cfg);
    engine.start();

    REQUIRE(engine.gossip_sent_count() == 0);
    REQUIRE(engine.gossip_received_count() == 0);

    engine.stop();
}

TEST_CASE("Benchmark validation - Merkle tree operations", "[benchmark][merkle]")
{
    using namespace smo::sync;

    MerkleTree tree(TreeID::Membership);
    tree.buckets.resize(256);

    for (int i = 0; i < 100; ++i)
    {
        MerkleNode node;
        node.data = Bytes(64, static_cast<uint8_t>(i));
        node.epoch = i;
        std::hash<BytesView> hasher;
        uint64_t h = hasher(BytesView{node.data.data(), node.data.size()});
        for (int j = 0; j < 32; ++j)
        {
            node.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
        }
        tree.buckets[i % 256] = node;
    }

    tree.rebuild();

    REQUIRE(tree.root_hash != std::array<uint8_t, 32>{});
    REQUIRE(tree.epoch == 0);

    auto serialized = tree.serialize();
    REQUIRE(!serialized.empty());

    auto result = MerkleTree::deserialize(serialized);
    REQUIRE(result.has_value());
    REQUIRE(result->root_hash == tree.root_hash);
}

TEST_CASE("Benchmark validation - Version vector merge", "[benchmark][version_vector]")
{
    using namespace smo::sync;

    VersionVector vv1, vv2;
    vv1.set(1, 10);
    vv1.set(2, 20);
    vv2.set(2, 25);
    vv2.set(3, 30);

    VersionVector merged = vv1.merge(vv2);

    REQUIRE(merged.get(1) == 10);
    REQUIRE(merged.get(2) == 25); // max of 20 and 25
    REQUIRE(merged.get(3) == 30);
}

TEST_CASE("Benchmark validation - Identity generation", "[benchmark][identity]")
{
    identity::Identity id1;
    id1.generate();

    identity::Identity id2;
    id2.generate();

    REQUIRE(id1.public_key() != id2.public_key());
    REQUIRE(id1.public_key().size() == 32);
    REQUIRE(id1.private_key().size() == 32);
}

TEST_CASE("Benchmark validation - Anti-entropy config defaults", "[benchmark][anti_entropy]")
{
    using namespace smo::sync;

    AntiEntropyService::Config cfg = AntiEntropyService::Config::defaults();

    REQUIRE(cfg.interval_ns == 1800'000'000'000ULL);
    REQUIRE(cfg.fanout == 3);
    REQUIRE(cfg.max_delta_entries == 500);
}

TEST_CASE("Benchmark validation - Gossip config defaults", "[benchmark][gossip_config]")
{
    GossipEngine::Config cfg = GossipEngine::default_config();

    REQUIRE(cfg.interval_ms == 5000);
    REQUIRE(cfg.fanout == 3);
    REQUIRE(cfg.max_payload == 65536);
}

TEST_CASE("Benchmark validation - Delta type enum", "[benchmark][delta_type]")
{
    using DeltaType = GossipEngine::DeltaType;

    REQUIRE(static_cast<uint8_t>(DeltaType::Membership) == 0);
    REQUIRE(static_cast<uint8_t>(DeltaType::CRL) == 1);
    REQUIRE(static_cast<uint8_t>(DeltaType::Policy) == 2);
    REQUIRE(static_cast<uint8_t>(DeltaType::Manifest) == 3);
    REQUIRE(static_cast<uint8_t>(DeltaType::Routing) == 4);
    REQUIRE(static_cast<uint8_t>(DeltaType::Contracts) == 5);
}

TEST_CASE("Benchmark validation - Tree ID enum", "[benchmark][tree_id]")
{
    using TreeID = smo::sync::TreeID;

    REQUIRE(static_cast<uint8_t>(TreeID::Membership) == 0);
    REQUIRE(static_cast<uint8_t>(TreeID::CRL) == 1);
    REQUIRE(static_cast<uint8_t>(TreeID::Policy) == 2);
    REQUIRE(static_cast<uint8_t>(TreeID::Contract) == 3);

    REQUIRE(smo::sync::tree_name(TreeID::Membership) == "membership");
    REQUIRE(smo::sync::tree_name(TreeID::CRL) == "crl");
    REQUIRE(smo::sync::tree_name(TreeID::Policy) == "policy");
    REQUIRE(smo::sync::tree_name(TreeID::Contract) == "contract");

    REQUIRE(smo::sync::tree_bucket_count(TreeID::Membership) == 256);
    REQUIRE(smo::sync::tree_bucket_count(TreeID::CRL) == 256);
    REQUIRE(smo::sync::tree_bucket_count(TreeID::Policy) == 64);
    REQUIRE(smo::sync::tree_bucket_count(TreeID::Contract) == 64);
}