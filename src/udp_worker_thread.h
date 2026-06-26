// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_WORKER_THREAD_H
#define CLV_VPN_UDP_WORKER_THREAD_H

#include "cpu_affinity.h"

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <optional>
#include <string>
#include <thread>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/**
 * @brief Dedicated worker thread for split-datapath mode.
 *
 * Owns a private asio::io_context and std::jthread.  Callers co_spawn
 * coroutines onto context(); the worker thread drives them.
 *
 * Lifecycle: construct → Start() → co_spawn work onto context() → Stop().
 * Stop() is also called by the destructor if still running.
 */
class UdpWorkerThread
{
  public:
    /**
     * @param name          Human-readable label for log messages (e.g. "TX", "RX").
     * @param cpu_affinity  CPU core to pin the worker to.
     *                      kAffinityOff (-1) = no pinning.
     *                      kAffinityAuto (-2) = pin to scheduler-chosen core.
     *                      ≥0 = explicit core index.
     * @param logger        Logger for lifecycle messages.
     */
    explicit UdpWorkerThread(std::string name, int cpu_affinity, spdlog::logger &logger);

    ~UdpWorkerThread();

    UdpWorkerThread(const UdpWorkerThread &) = delete;
    UdpWorkerThread &operator=(const UdpWorkerThread &) = delete;
    UdpWorkerThread(UdpWorkerThread &&) = delete;
    UdpWorkerThread &operator=(UdpWorkerThread &&) = delete;

    /** Start the worker thread.  Idempotent — second call is a no-op. */
    void Start();

    /**
     * Stop the worker thread and join it.
     * Safe to call multiple times.  After Stop(), context() must not be used.
     */
    void Stop();

    /** The io_context driven by the worker thread.  co_spawn work here. */
    asio::io_context &context() noexcept
    {
        return ctx_;
    }

    /** True between Start() and Stop(). */
    bool running() const noexcept
    {
        return running_.load(std::memory_order_relaxed);
    }

  private:
    asio::io_context ctx_;
    using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;
    std::optional<WorkGuard> work_guard_;
    std::jthread thread_;
    std::atomic<bool> running_{false};

    std::string name_;
    int cpu_affinity_;
    int claimed_core_ = kAffinityOff; ///< Core claimed via CpuCoreAllocator::Claim; released on Stop().
    spdlog::logger &logger_;
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_WORKER_THREAD_H
