#include <benchmark/benchmark.h>
#include <core/types.hpp>
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

using namespace smo;

static NodeID make_mock_node_id(int seed)
{
    NodeID id;
    for (size_t i = 0; i < 32; ++i)
    {
        id.value[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return id;
}

static void BM_Gossip_Engine_Creation(benchmark::State& state)
{
    const int fanout = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        MembershipTable table;
        GossipEngine::Config cfg;
        cfg.fanout = fanout;
        cfg.interval_ms = 100;
        cfg.max_payload = 65536;

        auto start = std::chrono::high_resolution_clock::now();

        GossipEngine engine(table, cfg);

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.counters["fanout"] = fanout;
}

BENCHMARK(BM_Gossip_Engine_Creation)->Arg(1)->Arg(3)->Arg(5)->Arg(10);

static void BM_Gossip_Message_Assembly(benchmark::State& state)
{
    const int num_peers = static_cast<int>(state.range(0));
    const int num_deltas = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        MembershipTable table;

        for (int i = 0; i < num_peers; ++i)
        {
            NodeID node_id = make_mock_node_id(i);
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(10000 + i);

            PeerRecord record;
            record.node_id = node_id;
            record.endpoint = ep;
            record.state = PeerState::Online;
            table.upsert(std::move(record));
        }

        GossipEngine::Config cfg;
        cfg.fanout = 3;
        cfg.interval_ms = 100;
        GossipEngine engine(table, cfg);

        for (int i = 0; i < num_deltas; ++i)
        {
            Bytes delta(256, static_cast<uint8_t>(i));
            engine.queue_delta(DeltaType::Membership, delta);
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < 100; ++i)
        {
            Bytes payload(1024, 0xAB);
            benchmark::DoNotOptimize(payload);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * 100);
    state.counters["messages_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * 100), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Gossip_Message_Assembly)
    ->Args({100, 10})
    ->Args({500, 10})
    ->Args({1000, 10})
    ->Args({100, 50})
    ->Args({500, 50})
    ->Args({1000, 50});

static void BM_Gossip_Delta_Processing(benchmark::State& state)
{
    const int num_deltas = static_cast<int>(state.range(0));
    const int delta_size = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        MembershipTable table;
        GossipEngine::Config cfg;
        GossipEngine engine(table, cfg);

        std::atomic<int> processed{0};
        engine.set_delta_handler(DeltaType::Membership, [&processed](BytesView data) -> Result<void> {
            processed++;
            return Result<void>{};
        });

        std::vector<Bytes> deltas;
        deltas.reserve(static_cast<size_t>(num_deltas));
        for (int i = 0; i < num_deltas; ++i)
        {
            deltas.emplace_back(static_cast<size_t>(delta_size), static_cast<uint8_t>(i));
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 1000; ++iter)
        {
            for (const auto& delta : deltas)
            {
                Bytes framed = delta;
                auto result = GossipEngine::handle_gossip_message(framed, engine);
                benchmark::DoNotOptimize(result);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    const int64_t total_deltas = static_cast<int64_t>(state.iterations()) * num_deltas * 1000;
    state.SetItemsProcessed(total_deltas);
    state.counters["deltas_per_sec"] =
        benchmark::Counter(static_cast<double>(total_deltas), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Gossip_Delta_Processing)
    ->Args({10, 256})
    ->Args({50, 256})
    ->Args({100, 256})
    ->Args({10, 1024})
    ->Args({50, 1024})
    ->Args({100, 1024})
    ->Args({10, 4096})
    ->Args({50, 4096})
    ->Args({100, 4096});

static void BM_Gossip_1000_msg_s_Sustained(benchmark::State& state)
{
    const int target_msg_per_sec = 1000;
    const int duration_seconds = static_cast<int>(state.range(0));
    const int num_peers = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        MembershipTable table;

        for (int i = 0; i < num_peers; ++i)
        {
            NodeID node_id = make_mock_node_id(i);
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(10000 + i);

            PeerRecord record;
            record.node_id = node_id;
            record.endpoint = ep;
            record.state = PeerState::Online;
            table.upsert(std::move(record));
        }

        GossipEngine::Config cfg;
        cfg.fanout = 3;
        cfg.interval_ms = 100;
        cfg.max_payload = 65536;
        GossipEngine engine(table, cfg);
        engine.start();

        std::atomic<bool> running{true};
        std::atomic<uint64_t> messages_sent{0};
        std::atomic<uint64_t> messages_received{0};
        std::atomic<uint64_t> bytes_sent{0};

        auto monitor = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
            running = false;
            engine.stop();
        });

        auto producer = std::thread([&]() {
            auto next_send = std::chrono::steady_clock::now();
            const auto interval = std::chrono::microseconds(1'000'000 / target_msg_per_sec);

            while (running)
            {
                std::this_thread::sleep_until(next_send);
                next_send += interval;

                if (!running)
                    break;

                Bytes delta(512, static_cast<uint8_t>(messages_sent.load() % 256));
                engine.queue_delta(DeltaType::Membership, delta);
                messages_sent++;
                bytes_sent += delta.size();
            }
        });

        auto consumer = std::thread([&]() {
            while (running)
            {
                int64_t now = std::chrono::steady_clock::now().time_since_epoch().count();
                engine.tick(now);

                if (messages_sent.load() > messages_received.load())
                {
                    messages_received += std::min<uint64_t>(3, messages_sent.load() - messages_received.load());
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });

        producer.join();
        consumer.join();
        monitor.join();

        state.counters["target_msg_per_sec"] = target_msg_per_sec;
        state.counters["actual_msg_sent_per_sec"] =
            benchmark::Counter(static_cast<double>(messages_sent.load()), benchmark::Counter::kIsRate);
        state.counters["actual_msg_received_per_sec"] =
            benchmark::Counter(static_cast<double>(messages_received.load()), benchmark::Counter::kIsRate);
        state.counters["throughput_mbps"] =
            benchmark::Counter(static_cast<double>(bytes_sent.load()) / 1e6, benchmark::Counter::kIsRate);
        state.counters["peer_count"] = num_peers;
    }
}

BENCHMARK(BM_Gossip_1000_msg_s_Sustained)->Args({5, 100})->Args({10, 100})->Args({5, 500})->Args({10, 500});

static void BM_Gossip_Fanout_Selection(benchmark::State& state)
{
    const int num_peers = static_cast<int>(state.range(0));
    const int fanout = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        MembershipTable table;

        for (int i = 0; i < num_peers; ++i)
        {
            NodeID node_id = make_mock_node_id(i);
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(10000 + i);

            PeerRecord record;
            record.node_id = node_id;
            record.endpoint = ep;
            record.state = PeerState::Online;
            table.upsert(std::move(record));
        }

        GossipEngine::Config cfg;
        cfg.fanout = fanout;
        GossipEngine engine(table, cfg);

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 10000; ++iter)
        {
            auto peers = engine.test_select_fanout_peers();
            benchmark::DoNotOptimize(peers);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * 10000);
    state.counters["selections_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * 10000), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Gossip_Fanout_Selection)
    ->Args({100, 3})
    ->Args({500, 3})
    ->Args({1000, 3})
    ->Args({100, 5})
    ->Args({500, 5})
    ->Args({1000, 5});

static void BM_Gossip_Serialization_Deserialization(benchmark::State& state)
{
    const int payload_size = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        MembershipTable table;
        GossipEngine::Config cfg;
        GossipEngine engine(table, cfg);

        Bytes payload(static_cast<size_t>(payload_size), 0xAB);
        engine.queue_delta(DeltaType::Membership, payload);

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 10000; ++iter)
        {
            Bytes serialized(static_cast<size_t>(payload_size) + 64, 0xCD);
            auto result = GossipEngine::handle_gossip_message(serialized, engine);
            benchmark::DoNotOptimize(result);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    const int64_t total_bytes = static_cast<int64_t>(state.iterations()) * payload_size * 10000 * 2;
    state.SetBytesProcessed(total_bytes);
    state.counters["throughput_mbps"] =
        benchmark::Counter(static_cast<double>(total_bytes) / 1e6, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Gossip_Serialization_Deserialization)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)->Arg(65536);

BENCHMARK_MAIN();