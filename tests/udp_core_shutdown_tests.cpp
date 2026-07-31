// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "cpu_affinity.h"
#include "p2p_policy.h"
#include "udp_core.h"

#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <gtest/gtest.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <future>
#include <thread>
#include <utility>
#include <vector>

using namespace clv::vpn;

namespace {

spdlog::logger &TestLogger()
{
    static auto sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    static spdlog::logger logger("test_udp_core_shutdown", sink);
    return logger;
}

/// Minimal CRTP engine so the test can call CoreStart / CoreStop directly.
struct TestEngine : UdpCore<TestEngine, P2PPolicy>
{
    TestEngine(Config config, asio::io_context &control_ctx, spdlog::logger &logger)
        : UdpCore(std::move(config), control_ctx, logger)
    {
    }

    using UdpCore::CoreStart;
    using UdpCore::CoreStop;

    void OnControlPacket(std::vector<std::uint8_t>, transport::PeerEndpoint) {}
    void OnRxActivity() {}
};

} // namespace

// Mirrors simple_vpn: CoreStart runs on the control io_context thread while
// Disconnect() / StopDataPath() calls CoreStop from the supervisor thread.
TEST(UdpCoreShutdown, ConcurrentStopDuringStart)
{
    asio::io_context ctx;
    auto work = asio::make_work_guard(ctx);
    std::jthread runner([&] { ctx.run(); });

    TestEngine engine(TestEngine::Config{.cpu_affinity = kAffinityOff, .tx_affinity = kAffinityOff},
                      ctx,
                      TestLogger());

    std::atomic<bool> stop_hammer{false};
    std::jthread hammer([&]
    {
        while (!stop_hammer.load(std::memory_order_relaxed))
            engine.CoreStop();
    });

    constexpr int kIters = 200;
    for (int i = 0; i < kIters; ++i)
    {
        std::promise<void> done;
        auto fut = done.get_future();
        asio::post(ctx, [&]
        {
            engine.CoreStart();
            done.set_value();
        });
        fut.wait();
    }

    stop_hammer.store(true, std::memory_order_relaxed);
    hammer.join();
    engine.CoreStop();
    work.reset();
    ctx.stop();
}
