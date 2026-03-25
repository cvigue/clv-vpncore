// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CPU_AFFINITY_H
#define CLV_VPN_CPU_AFFINITY_H

#include <string>

namespace spdlog {
class logger;
}

/** Sentinel: no CPU pinning (default). */
constexpr int kAffinityOff = -1;
/** Sentinel: auto-pin to the core the scheduler already chose. */
constexpr int kAffinityAuto = -2;

/**
 * Pin the calling thread to a single CPU core.
 *
 * @param core  Logical CPU index (0-based), or kAffinityAuto to query
 *              sched_getcpu() and pin to whatever core the scheduler chose.
 *              kAffinityOff is a no-op that returns true.
 * @param logger  Logger for info/warn messages.
 * @return true on success (or no-op), false if the syscall failed.
 */
bool SetThreadAffinity(int core, spdlog::logger &logger);

/**
 * Unpin the calling thread (restore full CPU mask).
 * @return true on success.
 */
bool ClearThreadAffinity(spdlog::logger &logger);

/**
 * Return the logical CPU the calling thread is currently running on.
 * @return core index, or -1 on failure.
 */
int GetCurrentCpu();

/**
 * Return a human-readable description of a cpu_affinity config value.
 * Used for startup logging.
 */
std::string AffinityModeString(int value);

#endif // CLV_VPN_CPU_AFFINITY_H
