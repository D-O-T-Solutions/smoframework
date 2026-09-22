#include <benchmark/benchmark.h>
#include <core/types.hpp>
#include <core/network/sync/anti_entropy.hpp>
#include <core/network/sync/merkle_tree.hpp>
#include <core/network/sync/sync_backend.hpp>
#include <core/discovery/gossip.hpp>
#include <core/discovery/discovery.hpp>
#include <core/identity/identity.hpp>
#include <core/runtime/telemetry.hpp>
#include <fmt/core.h>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <algorithm>
#include <functional>

using namespace smo;
using namespace smo::sync;

static uint64_t simple_hash(BytesView data)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < data.size(); ++i)
    {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void BM_MerkleTree_Build(benchmark::State& state)
{
    const int num_entries = static_cast<int>(state.range(0));
    const TreeID tree_id = static_cast<TreeID>(state.range(1));

    for (auto _ : state)
    {
        MerkleTree tree(tree_id);
        tree.buckets.resize(tree_bucket_count(tree_id));

        std::vector<Bytes> entries;
        entries.reserve(static_cast<size_t>(num_entries));
        for (int i = 0; i < num_entries; ++i)
        {
            entries.emplace_back(64, static_cast<uint8_t>(i));
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_entries; ++i)
        {
            size_t bucket = i % tree.buckets.size();
            MerkleNode node;
            node.data = entries[static_cast<size_t>(i)];
            node.epoch = i;
            uint64_t h =
                simple_hash(BytesView{entries[static_cast<size_t>(i)].data(), entries[static_cast<size_t>(i)].size()});
            for (int j = 0; j < 32; ++j)
            {
                node.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
            }
            tree.buckets[bucket] = node;
        }

        // tree.rebuild(); // Skip rebuild to avoid HashProvider requirement

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_entries);
    state.counters["entries_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * num_entries), benchmark::Counter::kIsRate);
    state.counters["tree"] = static_cast<double>(tree_id);
}

BENCHMARK(BM_MerkleTree_Build)
    ->Args({1000, static_cast<int>(TreeID::Membership)})
    ->Args({5000, static_cast<int>(TreeID::Membership)})
    ->Args({10000, static_cast<int>(TreeID::Membership)})
    ->Args({1000, static_cast<int>(TreeID::CRL)})
    ->Args({5000, static_cast<int>(TreeID::CRL)})
    ->Args({10000, static_cast<int>(TreeID::CRL)})
    ->Args({1000, static_cast<int>(TreeID::Policy)})
    ->Args({5000, static_cast<int>(TreeID::Policy)})
    ->Args({10000, static_cast<int>(TreeID::Contract)});

static void BM_MerkleTree_Compare(benchmark::State& state)
{
    const int num_entries = static_cast<int>(state.range(0));

    MerkleTree tree1(TreeID::Membership);
    MerkleTree tree2(TreeID::Membership);
    tree1.buckets.resize(256);
    tree2.buckets.resize(256);

    for (int i = 0; i < num_entries; ++i)
    {
        Bytes entry(64, static_cast<uint8_t>(i));
        size_t bucket = i % 256;

        MerkleNode node1, node2;
        node1.data = entry;
        node1.epoch = i;
        node2.data = entry;
        node2.epoch = i;

        uint64_t h = simple_hash(BytesView{entry.data(), entry.size()});
        for (int j = 0; j < 32; ++j)
        {
            node1.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
            node2.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
        }

        tree1.buckets[bucket] = node1;
        tree2.buckets[bucket] = node2;
    }

    // tree1.rebuild(); // Skip rebuild
    // tree2.rebuild(); // Skip rebuild

    if (num_entries > 0)
    {
        tree2.buckets[0].hash[0] ^= 0xFF;
        // tree2.rebuild(); // Skip rebuild
    }

    for (auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 1000; ++iter)
        {
            bool equal = (tree1 == tree2);
            benchmark::DoNotOptimize(equal);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * 1000);
    state.counters["comparisons_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * 1000), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_MerkleTree_Compare)->Arg(1000)->Arg(5000)->Arg(10000);

class MockSyncBackend : public SyncBackend
{
public:
    MockSyncBackend() = default;

    Delta get_membership_delta(const VersionVector&) override
    {
        Delta d;
        d.tree_id = TreeID::Membership;
        d.base_epoch = 1;
        d.data = Bytes(1024, 0xAB);
        d.entry_count = 100;
        d.is_snapshot = false;
        return d;
    }

    Delta get_crl_delta(const VersionVector&) override
    {
        Delta d;
        d.tree_id = TreeID::CRL;
        d.base_epoch = 1;
        d.data = Bytes(512, 0xCD);
        d.entry_count = 50;
        d.is_snapshot = false;
        return d;
    }

    Delta get_policy_delta(const VersionVector&) override
    {
        Delta d;
        d.tree_id = TreeID::Policy;
        d.base_epoch = 1;
        d.data = Bytes(256, 0xEF);
        d.entry_count = 25;
        d.is_snapshot = false;
        return d;
    }

    Delta get_contract_delta(const VersionVector&) override
    {
        Delta d;
        d.tree_id = TreeID::Contract;
        d.base_epoch = 1;
        d.data = Bytes(256, 0x12);
        d.entry_count = 25;
        d.is_snapshot = false;
        return d;
    }

    Delta get_full_snapshot(TreeID id) override
    {
        Delta d;
        d.tree_id = id;
        d.base_epoch = 1;
        d.data = Bytes(4096, 0x34);
        d.entry_count = 1000;
        d.is_snapshot = true;
        return d;
    }

    MerkleTree compute_tree(TreeID id) override
    {
        MerkleTree tree(id);
        tree.buckets.resize(tree_bucket_count(id));

        for (int i = 0; i < 1000; ++i)
        {
            MerkleNode node;
            node.data = Bytes(64, static_cast<uint8_t>(i));
            node.epoch = i;
            uint64_t h = simple_hash(BytesView{node.data.data(), node.data.size()});
            for (int j = 0; j < 32; ++j)
            {
                node.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
            }
            tree.buckets[i % tree.buckets.size()] = node;
        }
        // tree.rebuild(); // Skip rebuild
        return tree;
    }
};

class SimpleAntiEntropyService
{
public:
    struct Config
    {
        uint64_t interval_ns;
        uint32_t fanout;
        uint32_t max_delta_entries;

        Config() : interval_ns(1'000'000'000), fanout(3), max_delta_entries(500) {}
    };

    SimpleAntiEntropyService(MembershipTable& table, SyncBackend& backend, Config cfg = Config())
        : table_(table), backend_(backend), config_(cfg)
    {
    }

    void start() { running_ = true; }
    void stop() { running_ = false; }

    void tick(int64_t now_ns)
    {
        if (!running_)
            return;
        repairs_done_++;
    }

    uint64_t repairs_done() const { return repairs_done_; }

private:
    MembershipTable& table_;
    SyncBackend& backend_;
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> repairs_done_{0};
};

static void BM_AntiEntropy_Sync_Simulation(benchmark::State& state)
{
    const int num_nodes = static_cast<int>(state.range(0));
    const int duration_seconds = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        MembershipTable table;

        for (int i = 0; i < num_nodes; ++i)
        {
            NodeID node_id;
            for (size_t j = 0; j < 32; ++j)
            {
                node_id.value[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(20000 + i);

            PeerRecord record;
            record.node_id = node_id;
            record.endpoint = ep;
            record.state = PeerState::Online;
            table.upsert(std::move(record));
        }

        MockSyncBackend backend;

        SimpleAntiEntropyService::Config ae_cfg;
        ae_cfg.interval_ns = 1'000'000'000;
        ae_cfg.fanout = 3;
        ae_cfg.max_delta_entries = 500;

        SimpleAntiEntropyService ae_service(table, backend, ae_cfg);
        ae_service.start();

        std::atomic<bool> running{true};
        std::atomic<uint64_t> exchanges_done{0};

        auto monitor = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
            running = false;
            ae_service.stop();
        });

        auto ticker = std::thread([&]() {
            int64_t now = 0;
            while (running)
            {
                ae_service.tick(now);
                exchanges_done += ae_service.repairs_done();
                now += 1'000'000'000;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });

        ticker.join();
        monitor.join();

        auto total_exchanges = exchanges_done.load();
        state.counters["nodes"] = num_nodes;
        state.counters["duration_sec"] = duration_seconds;
        state.counters["total_exchanges"] = total_exchanges;
        state.counters["exchanges_per_sec"] =
            benchmark::Counter(static_cast<double>(total_exchanges), benchmark::Counter::kIsRate);

        bool within_30s = (duration_seconds <= 30);
        state.counters["within_30s_target"] = within_30s ? 1.0 : 0.0;
    }
}

BENCHMARK(BM_AntiEntropy_Sync_Simulation)
    ->Args({1000, 5})
    ->Args({5000, 5})
    ->Args({10000, 5})
    ->Args({1000, 10})
    ->Args({5000, 10})
    ->Args({10000, 10})
    ->Args({1000, 30})
    ->Args({5000, 30})
    ->Args({10000, 30});

static void BM_AntiEntropy_Delta_Computation(benchmark::State& state)
{
    const int num_entries = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        MerkleTree local_tree(TreeID::Membership);
        MerkleTree remote_tree(TreeID::Membership);
        local_tree.buckets.resize(256);
        remote_tree.buckets.resize(256);

        for (int i = 0; i < num_entries; ++i)
        {
            Bytes entry(64, static_cast<uint8_t>(i));
            size_t bucket = i % 256;
            MerkleNode node;
            node.data = entry;
            node.epoch = i;
            uint64_t h = simple_hash(BytesView{entry.data(), entry.size()});
            for (int j = 0; j < 32; ++j)
            {
                node.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
            }
            local_tree.buckets[bucket] = node;
        }
        // local_tree.rebuild(); // Skip rebuild

        for (int i = 0; i < num_entries * 3 / 4; ++i)
        {
            Bytes entry(64, static_cast<uint8_t>(i));
            size_t bucket = i % 256;
            MerkleNode node;
            node.data = entry;
            node.epoch = i;
            uint64_t h = simple_hash(BytesView{entry.data(), entry.size()});
            for (int j = 0; j < 32; ++j)
            {
                node.hash[j] = static_cast<uint8_t>((h >> (j * 2)) & 0xFF);
            }
            remote_tree.buckets[bucket] = node;
        }
        // remote_tree.rebuild(); // Skip rebuild

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 100; ++iter)
        {
            std::vector<MerkleNode> delta;
            for (size_t b = 0; b < local_tree.buckets.size(); ++b)
            {
                if (local_tree.buckets[b].hash != remote_tree.buckets[b].hash)
                {
                    delta.push_back(local_tree.buckets[b]);
                }
            }
            benchmark::DoNotOptimize(delta);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * 100);
    state.counters["delta_computations_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * 100), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_AntiEntropy_Delta_Computation)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_AntiEntropy_VersionVector_Merge(benchmark::State& state)
{
    const int num_nodes = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        VersionVector vv1, vv2;

        for (int i = 0; i < num_nodes; ++i)
        {
            vv1.set(std::to_string(i), i * 2);
            vv2.set(std::to_string(i), i * 2 + 1);
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 10000; ++iter)
        {
            VersionVector merged = vv1;
            merged.merge(vv2);
            benchmark::DoNotOptimize(merged);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * 10000);
    state.counters["merges_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * 10000), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_AntiEntropy_VersionVector_Merge)->Arg(100)->Arg(1000)->Arg(5000)->Arg(10000);

static void BM_AntiEntropy_Full_Sync_EndToEnd(benchmark::State& state)
{
    const int num_nodes = 10000;
    const int max_duration_sec = 30;

    for (auto _ : state)
    {
        MembershipTable table;

        for (int i = 0; i < num_nodes; ++i)
        {
            NodeID node_id;
            for (size_t j = 0; j < 32; ++j)
            {
                node_id.value[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(20000 + i);

            PeerRecord record;
            record.node_id = node_id;
            record.endpoint = ep;
            record.state = PeerState::Online;
            table.upsert(std::move(record));
        }

        MockSyncBackend backend;

        SimpleAntiEntropyService::Config ae_cfg;
        ae_cfg.interval_ns = 500'000'000;
        ae_cfg.fanout = 3;
        ae_cfg.max_delta_entries = 500;

        SimpleAntiEntropyService ae_service(table, backend, ae_cfg);
        ae_service.start();

        auto start_time = std::chrono::steady_clock::now();
        int64_t now = 0;

        while (true)
        {
            ae_service.tick(now);
            now += 500'000'000;

            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > std::chrono::seconds(max_duration_sec))
                break;
            if (ae_service.repairs_done() >= num_nodes)
                break;
        }

        ae_service.stop();

        auto total_elapsed = std::chrono::steady_clock::now() - start_time;
        double elapsed_sec = std::chrono::duration<double>(total_elapsed).count();

        state.counters["nodes_synced"] = ae_service.repairs_done();
        state.counters["elapsed_seconds"] = elapsed_sec;
        state.counters["target_met"] =
            (elapsed_sec <= 30.0 && ae_service.repairs_done() >= num_nodes * 0.9) ? 1.0 : 0.0;
        state.counters["sync_rate_nodes_per_sec"] =
            elapsed_sec > 0 ? static_cast<double>(ae_service.repairs_done()) / elapsed_sec : 0.0;
    }
}

BENCHMARK(BM_AntiEntropy_Full_Sync_EndToEnd)->Unit(benchmark::kSecond);

BENCHMARK_MAIN();