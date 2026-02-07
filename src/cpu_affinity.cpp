// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "cpu_affinity.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <sched.h> // sched_setaffinity, sched_getcpu, cpu_set_t
#include <string>
#include <unistd.h>  // sysconf
#include <algorithm> // std::min
#include <cerrno>
#include <cstring> // strerror

#include "data_path_stats.h"
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

    // "auto" and "adaptive" both start by querying current placement
    if (core == kAffinityAuto || core == kAffinityAdaptive)
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
    if (value == kAffinityAdaptive)
        return "adaptive";
    return std::to_string(value);
}

// ---------------------------------------------------------------------------
// AdaptiveAffinityController
// ---------------------------------------------------------------------------

/// Bin midpoints for linear bins (width from DataPathStats::kBinWidth).
static constexpr double kBinMidpoints[clv::vpn::DataPathStats::kBatchHistBins] = {
    256.0, 768.0, 1280.0, 1792.0, 2304.0, 2816.0, 3328.0, 3840.0};

double AdaptiveAffinityController::WeightedAvgBatch(
    const std::array<std::uint64_t, kBatchHistBins> &hist)
{
    double weighted_sum = 0;
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < hist.size(); ++i)
    {
        weighted_sum += kBinMidpoints[i] * static_cast<double>(hist[i]);
        total += hist[i];
    }
    return total > 0 ? weighted_sum / static_cast<double>(total) : 0.0;
}

AdaptiveAffinityController::AdaptiveAffinityController(
    const AdaptiveAffinityConfig &cfg, spdlog::logger &logger)
    : cfg_(cfg), logger_(logger),
      throughput_ema_(cfg.ema_alpha), batch_avg_ema_(cfg.ema_alpha),
      window_start_(std::chrono::steady_clock::now())
{
    // Initial pin — same as "auto"
    int current = GetCurrentCpu();
    if (current >= 0)
    {
        pinned_core_ = current;
        SetThreadAffinity(current, logger_);
        logger_.info("adaptive affinity: initial pin to CPU {}, "
                     "baseline_windows={} probe_interval={} probe_duration={} "
                     "window={:.1f}s ema_alpha={:.2f} threshold={:.0f}%",
                     current,
                     cfg_.baseline_windows,
                     cfg_.probe_interval,
                     cfg_.probe_duration,
                     cfg_.window_seconds,
                     cfg_.ema_alpha,
                     cfg_.throughput_threshold * 100.0);
    }
}

void AdaptiveAffinityController::OnRecvBatch(std::size_t batch_size)
{
    // Accumulate (integer ops only — ~1-2 ns)
    window_packets_ += batch_size;
    window_hist_[static_cast<unsigned>(
        std::min(batch_size / kBinWidth, kBatchHistBins - 1))]++;
    ++recv_calls_;

    // Count-gated clock check
    if (recv_calls_ < kCallsPerCheck)
        return;
    recv_calls_ = 0;

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - window_start_).count();
    if (elapsed < cfg_.window_seconds)
        return;

    // Window complete — snapshot, reset accumulators, process
    window_start_ = now;
    std::uint64_t packets = window_packets_;
    auto hist = window_hist_;
    window_packets_ = 0;
    window_hist_.fill(0);

    ProcessWindow(packets, hist, elapsed);
}

void AdaptiveAffinityController::ProcessWindow(
    std::uint64_t packets,
    const std::array<std::uint64_t, kBatchHistBins> &hist,
    double elapsed_sec)
{
    double pps = elapsed_sec > 0 ? static_cast<double>(packets) / elapsed_sec : 0.0;
    double batch_avg = WeightedAvgBatch(hist);

    // Skip idle windows — no useful signal
    if (packets == 0)
        return;

    switch (state_)
    {
    case State::Baseline:
        {
            if (baseline_count_ == 0)
            {
                throughput_ema_.Reset(pps);
                batch_avg_ema_.Reset(batch_avg);
            }
            else
            {
                throughput_ema_.Update(pps);
                batch_avg_ema_.Update(batch_avg);
            }
            ++baseline_count_;

            if (baseline_count_ >= cfg_.baseline_windows)
            {
                state_ = State::Monitoring;
                monitor_count_ = 0;
                consec_degraded_ = 0;
                logger_.debug("adaptive affinity: baseline established "
                              "(pps_ema={:.0f} batch_avg_ema={:.1f}), entering monitoring",
                              throughput_ema_.Update(pps),
                              batch_avg_ema_.Update(batch_avg));
            }
            break;
        }

    case State::Monitoring:
        {
            double smoothed_pps = throughput_ema_.Update(pps);
            double smoothed_batch = batch_avg_ema_.Update(batch_avg);
            ++monitor_count_;

            // Detect degradation: throughput fell AND batch sizes grew
            // (batch growing = recv buffer accumulating = we're the bottleneck)
            bool throughput_degraded = pps < smoothed_pps * cfg_.throughput_threshold;
            bool batch_shifted_right = batch_avg > smoothed_batch * 1.25;

            if (throughput_degraded && batch_shifted_right)
                ++consec_degraded_;
            else
                consec_degraded_ = 0;

            // Require 3 consecutive degraded windows to avoid false positives
            bool should_probe = (consec_degraded_ >= 3) || (monitor_count_ >= cfg_.probe_interval);

            if (should_probe)
            {
                ClearThreadAffinity(logger_);
                int prev_core = pinned_core_;
                pinned_core_ = -1;
                state_ = State::Probing;
                probe_count_ = 0;

                if (consec_degraded_ >= 3)
                {
                    logger_.debug("adaptive affinity: degradation detected "
                                  "(pps={:.0f} vs ema={:.0f}, batch_avg={:.1f} vs ema={:.1f}), "
                                  "unpinned from CPU {} for {} windows",
                                  pps,
                                  smoothed_pps,
                                  batch_avg,
                                  smoothed_batch,
                                  prev_core,
                                  cfg_.probe_duration);
                }
                else
                {
                    logger_.debug("adaptive affinity: periodic probe, "
                                  "unpinned from CPU {} for {} windows",
                                  prev_core,
                                  cfg_.probe_duration);
                }
                consec_degraded_ = 0;
            }
            break;
        }

    case State::Probing:
        {
            ++probe_count_;

            if (probe_count_ >= cfg_.probe_duration)
            {
                int new_core = GetCurrentCpu();
                if (new_core >= 0)
                {
                    SetThreadAffinity(new_core, logger_);
                    pinned_core_ = new_core;
                    logger_.debug("adaptive affinity: probe complete, "
                                  "re-pinned to CPU {}",
                                  new_core);
                }

                // Reset EMA baselines for the new core
                throughput_ema_.Reset(pps);
                batch_avg_ema_.Reset(batch_avg);
                baseline_count_ = 1;
                state_ = State::Baseline;
            }
            break;
        }
    }
}
