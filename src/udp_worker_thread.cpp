// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "udp_worker_thread.h"

#include "cpu_affinity.h"

#include <spdlog/spdlog.h>

namespace clv::vpn {

UdpWorkerThread::UdpWorkerThread(std::string name, int cpu_affinity, spdlog::logger &logger)
    : name_(std::move(name)), cpu_affinity_(cpu_affinity), logger_(logger)
{
}

UdpWorkerThread::~UdpWorkerThread()
{
    Stop();
}

void UdpWorkerThread::Start()
{
    if (running_.exchange(true, std::memory_order_acq_rel))
        return; // already running

    work_guard_.emplace(ctx_.get_executor());

    thread_ = std::jthread([this](std::stop_token)
    {
        logger_.info("UdpWorkerThread[{}]: worker thread started (tid={})",
                     name_,
                     std::hash<std::thread::id>{}(std::this_thread::get_id()));

        if (cpu_affinity_ != kAffinityOff)
        {
            claimed_core_ = CpuCoreAllocator::Claim(cpu_affinity_);
            SetThreadAffinity(claimed_core_, logger_, "udp-worker");
        }

        ctx_.run();

        logger_.info("UdpWorkerThread[{}]: worker thread exiting", name_);
    });
}

void UdpWorkerThread::Stop()
{
    if (!running_.exchange(false, std::memory_order_acq_rel))
        return; // already stopped

    // Release work guard so io_context::run() can return once pending work drains.
    work_guard_.reset();
    ctx_.stop();

    if (thread_.joinable())
        thread_.join();

    CpuCoreAllocator::Release(claimed_core_);
    claimed_core_ = kAffinityOff;
}

} // namespace clv::vpn
