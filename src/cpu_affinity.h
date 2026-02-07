// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include "data_path_stats.h"
#include <pid_controller.h> // clv::ExponentialAverageFilter

namespace spdlog {
class logger;
}

/// Sentinel: no CPU pinning (default).
constexpr int kAffinityOff = -1;
/// Sentinel: auto-pin to the core the scheduler already chose.
constexpr int kAffinityAuto = -2;
/// Sentinel: adaptive mode — pin, monitor, probe, re-pin.
constexpr int kAffinityAdaptive = -3;

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

// ---------------------------------------------------------------------------
// Adaptive affinity — self-ticking from the recv hot path
// ---------------------------------------------------------------------------

/// Tunables for adaptive affinity mode.
struct AdaptiveAffinityConfig
{
    int probe_interval = 10;            ///< Windows between probes (quiet period)
    int probe_duration = 2;             ///< Windows to stay unpinned during a probe
    int baseline_windows = 5;           ///< Windows to seed the initial EMA
    double ema_alpha = 0.3;             ///< EMA smoothing factor (higher = more responsive)
    double throughput_threshold = 0.75; ///< Probe triggers when throughput < this fraction of EMA
    double window_seconds = 5.0;        ///< Minimum seconds per sampling window
};

/**
 * @brief Adaptive CPU affinity controller.
 *
 * Self-ticking: driven from the packet receive hot path via OnRecvBatch().
 * Internally accumulates packet counts and batch histogram, then every
 * kCallsPerCheck recvmmsg calls (~1000) checks the wall clock. When
 * window_seconds has elapsed, feeds accumulated data into the EMA/state
 * machine. Zero timers, zero coroutines, works even with stats disabled.
 *
 * State machine:  Baseline → Monitoring → Probing → Baseline → ...
 */
class AdaptiveAffinityController
{
  public:
    explicit AdaptiveAffinityController(const AdaptiveAffinityConfig &cfg, spdlog::logger &logger);

    /**
     * @brief Hot-path entry point — call after every recvmmsg.
     *
     * Internally count-gated: does an integer increment + compare per call
     * (~1 ns). Only reads the clock every kCallsPerCheck calls (~20 ns
     * amortized to ~0.02 ns/call). Feeds the state machine when a full
     * time window has elapsed.
     *
     * @param batch_size  Number of packets received in this recvmmsg call.
     */
    void OnRecvBatch(std::size_t batch_size);

    /// Current pinned core, or -1 if unpinned / not yet pinned.
    int PinnedCore() const
    {
        return pinned_core_;
    }

  private:
    static constexpr std::size_t kBatchHistBins = clv::vpn::DataPathStats::kBatchHistBins;
    static constexpr std::size_t kBinWidth = clv::vpn::DataPathStats::kBinWidth;

    /// How many recvmmsg calls between clock checks.
    static constexpr std::size_t kCallsPerCheck = 1000;

    /// Process one completed sampling window.
    void ProcessWindow(std::uint64_t packets,
                       const std::array<std::uint64_t, kBatchHistBins> &hist,
                       double elapsed_sec);

    enum class State
    {
        Baseline,   ///< Collecting initial samples to seed EMA
        Monitoring, ///< Steady-state: watching for degradation
        Probing     ///< Unpinned, letting scheduler choose
    };

    /// Compute weighted-average batch size from histogram.
    static double WeightedAvgBatch(const std::array<std::uint64_t, kBatchHistBins> &hist);

    AdaptiveAffinityConfig cfg_;
    spdlog::logger &logger_;
    State state_ = State::Baseline;

    int pinned_core_ = -1;    ///< Current pinned core (-1 = not pinned)
    int baseline_count_ = 0;  ///< Windows collected in Baseline state
    int monitor_count_ = 0;   ///< Windows since last probe
    int probe_count_ = 0;     ///< Windows elapsed in current probe
    int consec_degraded_ = 0; ///< Consecutive degraded windows

    clv::ExponentialAverageFilter<double> throughput_ema_;
    clv::ExponentialAverageFilter<double> batch_avg_ema_;

    // --- Hot-path accumulation state (single-threaded, no locking) ---
    std::size_t recv_calls_ = 0;                              ///< recvmmsg calls since last clock check
    std::uint64_t window_packets_ = 0;                        ///< Packets accumulated in current window
    std::array<std::uint64_t, kBatchHistBins> window_hist_{}; ///< Batch histogram for current window
    std::chrono::steady_clock::time_point window_start_;      ///< Start of current sampling window
};
