// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "cpu_affinity.h"

#include <sched.h> // sched_setaffinity, sched_getcpu, cpu_set_t
#include <string>
#include <unistd.h> // sysconf
#include <cerrno>
#include <cstring> // strerror

#include "spdlog/spdlog.h"

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

int GetCurrentCpu()
{
    return sched_getcpu();
}

bool SetThreadAffinity(int core, spdlog::logger &logger)
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

    logger.info("Reactor thread pinned to CPU {}", core);
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
