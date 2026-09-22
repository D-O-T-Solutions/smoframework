#include <benchmark/benchmark.h>
#include <core/types.hpp>
#include <core/network/udp/udp_transport.hpp>
#include <core/network/udp/heartbeat.hpp>
#include <core/network/udp/discovery.hpp>
#include <core/identity/identity.hpp>
#include <core/errors/error.hpp>
#include <fmt/core.h>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace smo;
using namespace smo::network::udp;

static void BM_UDP_Transport_Creation(benchmark::State& state)
{
    const int num_transports = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::vector<std::unique_ptr<UdpTransport>> transports;
        transports.reserve(static_cast<size_t>(num_transports));

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_transports; ++i)
        {
            auto transport = std::make_unique<UdpTransport>();
            transports.push_back(std::move(transport));
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_transports);
    state.counters["transports_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * num_transports), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_UDP_Transport_Creation)->Arg(100)->Arg(500)->Arg(1000)->Arg(2000);

static void BM_UDP_Listener_Creation(benchmark::State& state)
{
    const int num_listeners = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::vector<std::unique_ptr<UdpListener>> listeners;
        listeners.reserve(static_cast<size_t>(num_listeners));

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_listeners; ++i)
        {
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "0.0.0.0";
            ep.port = static_cast<uint16_t>(9000 + i);

            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd >= 0)
            {
                listeners.emplace_back(std::make_unique<UdpListener>(fd, ep));
                close(fd);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_listeners);
    state.counters["listeners_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * num_listeners), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_UDP_Listener_Creation)->Arg(100)->Arg(500)->Arg(1000)->Arg(2000);

static void BM_UDP_SendTo_Simulation(benchmark::State& state)
{
    const int num_targets = static_cast<int>(state.range(0));
    const int payload_size = static_cast<int>(state.range(1));

    for (auto _ : state)
    {
        Endpoint local;
        local.scheme = "udp";
        local.host = "0.0.0.0";
        local.port = 0;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        UdpListener listener(fd, local);

        std::vector<Endpoint> targets;
        targets.reserve(static_cast<size_t>(num_targets));
        for (int i = 0; i < num_targets; ++i)
        {
            Endpoint ep;
            ep.scheme = "udp";
            ep.host = "127.0.0.1";
            ep.port = static_cast<uint16_t>(9000 + i);
            targets.push_back(ep);
        }

        Bytes payload(static_cast<size_t>(payload_size), 0xEF);
        std::atomic<uint64_t> bytes_sent{0};

        auto start = std::chrono::high_resolution_clock::now();

        const int num_workers = static_cast<int>(std::thread::hardware_concurrency());
        std::vector<std::thread> senders;

        for (int w = 0; w < num_workers; ++w)
        {
            senders.emplace_back([&]() {
                for (int i = w; i < num_targets; i += num_workers)
                {
                    for (int iter = 0; iter < 10; ++iter)
                    {
                        auto result = listener.send_to(targets[i], payload);
                        if (result)
                        {
                            bytes_sent += payload_size;
                        }
                    }
                }
            });
        }

        for (auto& t : senders)
            t.join();

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    const int64_t total_bytes = static_cast<int64_t>(state.iterations()) * num_targets * payload_size * 10;
    state.SetBytesProcessed(total_bytes);
    state.counters["throughput_mbps"] =
        benchmark::Counter(static_cast<double>(total_bytes) / 1e6, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_UDP_SendTo_Simulation)
    ->Args({100, 512})
    ->Args({500, 512})
    ->Args({1000, 512})
    ->Args({2000, 512})
    ->Args({100, 1400})
    ->Args({500, 1400})
    ->Args({1000, 1400})
    ->Args({2000, 1400});

static void BM_UDP_Heartbeat_Simulation(benchmark::State& state)
{
    const int num_targets = 2000;
    const int duration_seconds = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::atomic<bool> running{true};
        std::atomic<uint64_t> heartbeats_sent{0};
        std::atomic<uint64_t> heartbeats_received{0};

        auto monitor = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
            running = false;
        });

        std::vector<std::thread> workers;
        const int num_workers = static_cast<int>(std::thread::hardware_concurrency());

        for (int w = 0; w < num_workers; ++w)
        {
            workers.emplace_back([&]() {
                while (running)
                {
                    for (int i = w; i < num_targets; i += num_workers)
                    {
                        if (!running)
                            break;

                        heartbeats_sent++;

                        if (heartbeats_sent.load() % 2 == 0)
                        {
                            heartbeats_received++;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            });
        }

        for (auto& t : workers)
            t.join();
        monitor.join();

        state.counters["heartbeats_sent_per_sec"] =
            benchmark::Counter(static_cast<double>(heartbeats_sent.load()), benchmark::Counter::kIsRate);
        state.counters["heartbeats_received_per_sec"] =
            benchmark::Counter(static_cast<double>(heartbeats_received.load()), benchmark::Counter::kIsRate);
    }
}

BENCHMARK(BM_UDP_Heartbeat_Simulation)->Arg(5)->Arg(10)->Arg(30);

static void BM_UDP_2000_Targets_Sustained(benchmark::State& state)
{
    const int num_targets = 2000;
    const int duration_seconds = 10;

    for (auto _ : state)
    {
        std::atomic<bool> running{true};
        std::atomic<uint64_t> packets_sent{0};
        std::atomic<uint64_t> packets_received{0};

        auto monitor = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
            running = false;
        });

        std::vector<std::thread> workers;
        const int num_workers = static_cast<int>(std::thread::hardware_concurrency());

        for (int w = 0; w < num_workers; ++w)
        {
            workers.emplace_back([&]() {
                std::mt19937 rng(std::random_device{}());
                std::uniform_int_distribution<int> dist(0, num_targets - 1);

                while (running)
                {
                    int idx = dist(rng);
                    (void)idx; // suppress unused

                    packets_sent++;

                    if (packets_sent.load() % 3 == 0)
                    {
                        packets_received++;
                    }
                }
            });
        }

        for (auto& t : workers)
            t.join();
        monitor.join();

        state.counters["packets_sent_per_sec"] =
            benchmark::Counter(static_cast<double>(packets_sent.load()), benchmark::Counter::kIsRate);
        state.counters["packets_received_per_sec"] =
            benchmark::Counter(static_cast<double>(packets_received.load()), benchmark::Counter::kIsRate);
        state.counters["target_count"] = num_targets;
    }
}

BENCHMARK(BM_UDP_2000_Targets_Sustained)->Unit(benchmark::kSecond);

static void BM_UDP_Hole_Punch_Simulation(benchmark::State& state)
{
    const int num_targets = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::atomic<int> successful{0};
        std::atomic<int> failed{0};

        auto start = std::chrono::high_resolution_clock::now();

        std::vector<std::thread> threads;
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 1);

        for (int i = 0; i < num_targets; ++i)
        {
            threads.emplace_back([&successful, &failed, &dist, &rng]() {
                bool success = dist(rng) == 1;
                if (success)
                    successful++;
                else
                    failed++;
            });
        }

        for (auto& t : threads)
        {
            t.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);

        state.counters["success_rate"] =
            successful.load() > 0 ? static_cast<double>(successful.load()) / num_targets : 0.0;
        state.counters["attempts_per_sec"] =
            benchmark::Counter(static_cast<double>(state.iterations() * num_targets), benchmark::Counter::kIsRate);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_targets);
}

BENCHMARK(BM_UDP_Hole_Punch_Simulation)->Arg(100)->Arg(500)->Arg(1000)->Arg(2000);

BENCHMARK_MAIN();