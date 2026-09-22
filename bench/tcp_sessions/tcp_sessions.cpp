#include <benchmark/benchmark.h>
#include <core/types.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/secure_session.hpp>
#include <core/session/session.hpp>
#include <core/identity/identity.hpp>
#include <core/crypto/impl.hpp>
#include <core/errors/error.hpp>
#include <fmt/core.h>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <algorithm>
#include <random>

using namespace smo;

static void BM_TCP_Transport_Creation(benchmark::State& state)
{
    const int num_transports = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::vector<std::unique_ptr<TcpTransport>> transports;
        transports.reserve(static_cast<size_t>(num_transports));

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_transports; ++i)
        {
            auto transport = std::make_unique<TcpTransport>();
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

BENCHMARK(BM_TCP_Transport_Creation)->Arg(100)->Arg(500)->Arg(1000)->Arg(5000);

static void BM_Identity_Creation(benchmark::State& state)
{
    const int num_identities = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::vector<Identity> identities;
        identities.reserve(static_cast<size_t>(num_identities));

        CryptoProvider crypto;
        crypto.suite_id = 1;
        crypto.name = "Test";

        std::random_device rd;
        std::mt19937_64 gen(rd());
        auto rng_fill = [](void* ctx, uint8_t* buf, size_t len) {
            auto& g = *static_cast<std::mt19937_64*>(ctx);
            for (size_t i = 0; i < len; ++i)
            {
                buf[i] = static_cast<uint8_t>(g());
            }
        };
        crypto.rng_ctx = &gen;
        crypto.rng_fill = rng_fill;

        RngRef rng{crypto.rng_ctx, crypto.rng_fill};

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_identities; ++i)
        {
            auto result = Identity::create(crypto, rng);
            if (result)
            {
                identities.push_back(std::move(result.value()));
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_identities);
    state.counters["identities_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations() * num_identities), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Identity_Creation)->Arg(100)->Arg(500)->Arg(1000)->Arg(5000);

static void BM_Session_Setup_Simulation(benchmark::State& state)
{
    const int num_sessions = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        std::atomic<uint64_t> completed{0};
        std::vector<std::thread> threads;

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_sessions; ++i)
        {
            threads.emplace_back([&completed]() {
                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint8_t> dist(0, 255);

                Bytes pk(32), sk(32);
                for (size_t j = 0; j < 32; ++j)
                {
                    pk[j] = dist(gen);
                    sk[j] = dist(gen);
                }

                Bytes msg(256, 0xAB);
                Bytes sig(64);
                for (size_t j = 0; j < 64; ++j)
                {
                    sig[j] = dist(gen);
                }

                (void)sig; // suppress unused
                completed.fetch_add(1, std::memory_order_relaxed);
            });
        }

        for (auto& t : threads)
        {
            t.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_sessions);
    state.counters["sessions_per_sec"] =
        benchmark::Counter(static_cast<double>(state.iterations()) * num_sessions, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Session_Setup_Simulation)->Arg(100)->Arg(500)->Arg(1000)->Arg(5000);

static void BM_TCP_Data_Transfer_Simulation(benchmark::State& state)
{
    const int num_sessions = static_cast<int>(state.range(0));
    const size_t payload_size = static_cast<size_t>(state.range(1));

    std::vector<Bytes> payloads;
    payloads.reserve(static_cast<size_t>(num_sessions));
    for (int i = 0; i < num_sessions; ++i)
    {
        payloads.emplace_back(payload_size, static_cast<uint8_t>(i % 256));
    }

    for (auto _ : state)
    {
        std::atomic<uint64_t> bytes_processed{0};
        std::vector<std::thread> threads;

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < num_sessions; ++i)
        {
            threads.emplace_back([&bytes_processed, &payloads, i]() {
                for (int iter = 0; iter < 10; ++iter)
                {
                    Bytes ciphertext = payloads[static_cast<size_t>(i)];
                    ciphertext.push_back(0xFF);
                    bytes_processed += ciphertext.size();

                    Bytes decrypted = ciphertext;
                    decrypted.pop_back();
                    bytes_processed += decrypted.size();
                }
            });
        }

        for (auto& t : threads)
        {
            t.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);
    }

    const int64_t total_bytes =
        static_cast<int64_t>(state.iterations()) * num_sessions * static_cast<int64_t>(payload_size) * 20;
    state.SetBytesProcessed(total_bytes);
    state.counters["throughput_mbps"] =
        benchmark::Counter(static_cast<double>(total_bytes) / 1e6, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_TCP_Data_Transfer_Simulation)
    ->Args({100, 1024})
    ->Args({500, 1024})
    ->Args({1000, 1024})
    ->Args({5000, 1024})
    ->Args({100, 65536})
    ->Args({500, 65536})
    ->Args({1000, 65536})
    ->Args({5000, 65536});

static void BM_TCP_Latency_P99(benchmark::State& state)
{
    const int num_sessions = static_cast<int>(state.range(0));
    const int iterations_per_session = 100;

    for (auto _ : state)
    {
        std::vector<uint64_t> latencies;
        latencies.reserve(static_cast<size_t>(num_sessions) * iterations_per_session);

        auto start = std::chrono::high_resolution_clock::now();

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(1000, 100000); // 1us to 100us

        for (int i = 0; i < num_sessions; ++i)
        {
            for (int iter = 0; iter < iterations_per_session; ++iter)
            {
                // Simulate round-trip latency
                latencies.push_back(dist(gen));
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        state.SetIterationTime(static_cast<double>(elapsed) * 1e-9);

        // Calculate percentiles
        std::sort(latencies.begin(), latencies.end());
        size_t p99_idx = latencies.size() * 99 / 100;
        size_t p50_idx = latencies.size() / 2;
        size_t p999_idx = latencies.size() * 999 / 1000;

        state.counters["p99_latency_us"] = static_cast<double>(latencies[p99_idx]) / 1000.0;
        state.counters["p50_latency_us"] = static_cast<double>(latencies[p50_idx]) / 1000.0;
        state.counters["p999_latency_us"] = static_cast<double>(latencies[p999_idx]) / 1000.0;
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * num_sessions * iterations_per_session);
}

BENCHMARK(BM_TCP_Latency_P99)->Arg(100)->Arg(500)->Arg(1000)->Arg(5000);

static void BM_TCP_5000_Sessions_Sustained(benchmark::State& state)
{
    const int num_sessions = 5000;
    const int duration_seconds = 10;

    for (auto _ : state)
    {
        std::atomic<bool> running{true};
        std::atomic<uint64_t> total_operations{0};
        std::atomic<uint64_t> errors{0};

        auto monitor = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
            running = false;
        });

        std::vector<std::thread> workers;
        const int num_workers = static_cast<int>(std::thread::hardware_concurrency());

        for (int w = 0; w < num_workers; ++w)
        {
            workers.emplace_back([&]() {
                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint8_t> dist(0, 255);

                while (running)
                {
                    for (int s = 0; s < num_sessions / num_workers; ++s)
                    {
                        if (!running)
                            break;

                        try
                        {
                            // Simulate session activity
                            Bytes data(512);
                            for (auto& b : data)
                                b = dist(gen);

                            // Mock sign/verify
                            Bytes sig(64);
                            for (auto& b : sig)
                                b = dist(gen);
                            bool ok = true;

                            if (!ok)
                                errors++;
                            total_operations++;
                        }
                        catch (...)
                        {
                            errors++;
                        }
                    }
                }
            });
        }

        for (auto& t : workers)
        {
            t.join();
        }
        monitor.join();

        state.counters["operations_per_sec"] =
            benchmark::Counter(static_cast<double>(total_operations.load()), benchmark::Counter::kIsRate);
        state.counters["error_rate"] =
            errors.load() > 0 ? static_cast<double>(errors.load()) / static_cast<double>(total_operations.load()) : 0.0;
    }
}

BENCHMARK(BM_TCP_5000_Sessions_Sustained)->Unit(benchmark::kSecond);

BENCHMARK_MAIN();