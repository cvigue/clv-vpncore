// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CPU_AFFINITY_H
#define CLV_VPN_CPU_AFFINITY_H

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

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
 * @param tag     Short identifier for the calling thread, e.g. "udp-worker".
 *                Appears in the log line as "[<tag>] pinned to CPU <n>".
 * @return true on success (or no-op), false if the syscall failed.
 */
bool SetThreadAffinity(int core, spdlog::logger &logger, std::string_view tag);

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

/**
 * @brief Process-wide CPU core allocation tracker.
 *
 * Maintains a per-process bitfield of claimed logical cores, used to prevent
 * concurrent kAffinityAuto assignments (or explicit assignments to the same
 * core) from mapping multiple threads to the same core.
 *
 * When Claim() encounters a conflict it walks forward from the requested
 * starting point and claims the first available core.  If every core in the
 * 64-bit bitfield is already claimed, it falls back gracefully: the requested
 * core is returned unclaimed so the thread can still pin.
 *
 * All methods are safe to call from any thread concurrently.
 */
class CpuCoreAllocator
{
  public:
    /**
     * @brief Claim a CPU core for the calling thread.
     *
     * @param requested  kAffinityOff — returns kAffinityOff (no pinning).
     *                   kAffinityAuto — uses sched_getcpu() as the starting
     *                   point, then finds the first unclaimed core from there.
     *                   ≥ 0 — claims that core; if already taken, walks
     *                   forward to the next available core.
     * @return The actual core claimed (≥ 0), or kAffinityOff if no pinning
     *         was requested.
     */
    static int Claim(int requested);

    /**
     * @brief Release a previously claimed core.
     *
     * No-op when @p core is negative (kAffinityOff or a failed claim).
     *
     * @param core  The value returned by Claim().
     */
    static void Release(int core);

    /**
     * @brief Reset all claimed cores to unclaimed.
     *
     * For unit tests only — do not call in production code.
     */
    static void ResetForTesting();

  private:
    static inline std::atomic<std::uint64_t> claimed_{0};
};

#endif // CLV_VPN_CPU_AFFINITY_H
