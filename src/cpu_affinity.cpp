// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "cpu_affinity.h"

#include <spdlog/spdlog.h>

#include <sched.h>  // sched_setaffinity, sched_getcpu, cpu_set_t
#include <unistd.h> // sysconf

#include <cerrno>
#include <cstring> // strerror
#include <string>
#include <string_view>

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

int GetCurrentCpu()
{
    return sched_getcpu();
}

bool SetThreadAffinity(int core, spdlog::logger &logger, std::string_view tag)
{
    if (core == kAffinityOff)
        return true; // no-op

    // "auto" queries current placement and pins there
    if (core == kAffinityAuto)
    {
        int current = GetCurrentCpu();
        if (current < 0)
        {
            logger.warn("cpu_affinity: sched_getcpu() failed: {}", std::strerror(errno));
            return false;
        }
        core = current;
    }

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1)
    {
        logger.warn("cpu_affinity: sysconf(_SC_NPROCESSORS_ONLN) failed: {}", std::strerror(errno));
        return false;
    }
    if (core < 0 || core >= nproc)
    {
        logger.warn("cpu_affinity: core {} out of range [0, {})", core, nproc);
        return false;
    }

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) != 0)
    {
        logger.warn("cpu_affinity: sched_setaffinity({}) failed: {}", core, std::strerror(errno));
        return false;
    }

    logger.info("[{}] pinned to CPU {}", tag, core);
    return true;
}

bool ClearThreadAffinity(spdlog::logger &logger)
{
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1)
    {
        logger.warn("cpu_affinity: sysconf(_SC_NPROCESSORS_ONLN) failed: {}", std::strerror(errno));
        return false;
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);
    for (long i = 0; i < nproc; ++i)
        CPU_SET(i, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) != 0)
    {
        logger.warn("cpu_affinity: ClearThreadAffinity failed: {}", std::strerror(errno));
        return false;
    }
    return true;
}

std::string AffinityModeString(int value)
{
    if (value == kAffinityOff)
        return "off";
    if (value == kAffinityAuto)
        return "auto";
    return std::to_string(value);
}

// ---------------------------------------------------------------------------
// CpuCoreAllocator
// ---------------------------------------------------------------------------

int CpuCoreAllocator::Claim(int requested)
{
    if (requested == kAffinityOff)
        return kAffinityOff;

    int start;
    if (requested == kAffinityAuto)
    {
        start = sched_getcpu();
        if (start < 0)
            start = 0;
    }
    else
    {
        start = requested;
    }

    const int nproc = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
    if (nproc < 1 || start < 0 || start >= 64)
        return (requested == kAffinityAuto) ? start : requested;

    // CAS loop: find first unclaimed core starting from `start` (wrapping),
    // then atomically claim it.
    std::uint64_t old = claimed_.load(std::memory_order_relaxed);
    while (true)
    {
        int core = -1;
        for (int i = 0; i < std::min(nproc, 64); ++i)
        {
            int candidate = (start + i) % std::min(nproc, 64);
            if (!(old & (std::uint64_t(1) << candidate)))
            {
                core = candidate;
                break;
            }
        }
        if (core < 0)
        {
            // All cores claimed — best-effort fallback without claiming.
            return start;
        }

        std::uint64_t desired = old | (std::uint64_t(1) << core);
        if (claimed_.compare_exchange_weak(old, desired, std::memory_order_acq_rel, std::memory_order_relaxed))
            return core;
        // CAS lost — old was reloaded by compare_exchange_weak, retry.
    }
}

void CpuCoreAllocator::Release(int core)
{
    if (core < 0 || core >= 64)
        return;
    claimed_.fetch_and(~(std::uint64_t(1) << core), std::memory_order_release);
}

void CpuCoreAllocator::ResetForTesting()
{
    claimed_.store(0, std::memory_order_relaxed);
}
