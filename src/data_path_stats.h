// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DATA_PATH_STATS_H
#define CLV_VPN_DATA_PATH_STATS_H

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace clv::vpn {

/**
 * @brief Monotonic counters for the UDP data path.
 *
 * In split-datapath mode (dedicated TX + RX threads) each thread owns its
 * own counter struct: the TX thread writes TxCounters, the RX thread writes
 * RxCounters.  Each field has exactly one writer — naturally-aligned 64-bit
 * stores are atomic on x86-64/aarch64, so the control thread can safely read
 * all fields for stats reporting.  Merge() produces a unified snapshot.
 *
 * In single-threaded mode (TCP) all fields live in one DataPathStats and
 * are accessed from the control io_context only.
 *
 * Counters only increase (never reset).  Consumers that need periodic deltas
 * use Delta() or StatsObserver.
 */
struct DataPathStats
{
    // --- Batch histogram (linear bins for recvmmsg batch sizes) ---
    // 8 bins × 512 packets: [0]=0-511  [1]=512-1023  [2]=1024-1535  [3]=1536-2047
    //                        [4]=2048-2559  [5]=2560-3071  [6]=3072-3583  [7]=3584-4095
    static constexpr std::size_t kBatchHistBins = 8;
    static constexpr std::size_t kBinWidth = 512;
    static constexpr std::size_t kRingOccBins = 4; ///< SPSC ring occupancy bins: empty/low/med/high

    /** Compute histogram bin index for a batch size (linear, width=512). */
    static unsigned BatchBin(std::size_t n)
    {
        return static_cast<unsigned>(
            std::min(n / kBinWidth, kBatchHistBins - 1));
    }

    // ---- Per-thread counter structs for split-datapath mode ----
    // In split mode, TX thread owns TxCounters, RX thread owns RxCounters.
    // No sharing on the hot path.  Merged at the stats interval.

    /** Counters owned exclusively by the RX thread (UDP recv → decrypt → TUN write). */
    struct RxCounters
    {
        std::uint64_t packetsReceived = 0;
        std::uint64_t bytesReceived = 0;
        std::array<std::uint64_t, kBatchHistBins> batchHist{};
        std::uint64_t batchSaturations = 0;
        std::uint64_t packetsDecrypted = 0;
        std::uint64_t decryptFailures = 0;
        std::uint64_t tunWrites = 0;

        void RecordRecvBatch(std::size_t n, std::size_t batchCapacity)
        {
            batchHist[BatchBin(n)]++;
            if (n == batchCapacity)
                ++batchSaturations;
        }
    };

    /** Counters owned exclusively by the TX thread (TUN read → encrypt → UDP send). */
    struct TxCounters
    {
        std::uint64_t tunReads = 0;
        std::uint64_t packetsEncrypted = 0;
        std::uint64_t packetsSent = 0;
        std::uint64_t bytesSent = 0;
        std::uint64_t packetsDroppedOnSend = 0;
        std::uint64_t sendErrors = 0;
        std::uint64_t routeLookupMisses = 0;
        std::uint64_t txSmallPktFlush = 0; ///< Early drain flushes triggered by small packet mid-batch
    };

    /** Build a unified DataPathStats from separate per-thread counters. */
    static DataPathStats Merge(const RxCounters &rx, const TxCounters &tx)
    {
        DataPathStats m;
        m.packetsReceived = rx.packetsReceived;
        m.bytesReceived = rx.bytesReceived;
        m.batchHist = rx.batchHist;
        m.batchSaturations = rx.batchSaturations;
        m.packetsDecrypted = rx.packetsDecrypted;
        m.decryptFailures = rx.decryptFailures;
        m.tunWrites = rx.tunWrites;
        m.tunReads = tx.tunReads;
        m.packetsEncrypted = tx.packetsEncrypted;
        m.packetsSent = tx.packetsSent;
        m.bytesSent = tx.bytesSent;
        m.packetsDroppedOnSend = tx.packetsDroppedOnSend;
        m.sendErrors = tx.sendErrors;
        m.routeLookupMisses = tx.routeLookupMisses;
        m.txSmallPktFlush = tx.txSmallPktFlush;
        return m;
    }

    // --- Receive path (UDP → decrypt → TUN) ---
    std::uint64_t packetsReceived = 0;                     ///< Total UDP datagrams received
    std::uint64_t bytesReceived = 0;                       ///< Total UDP bytes received
    std::array<std::uint64_t, kBatchHistBins> batchHist{}; ///< Per-bin recv batch counts
    std::uint64_t batchSaturations = 0;                    ///< recvmmsg returned exactly batchSize
    std::uint64_t packetsDecrypted = 0;
    std::uint64_t decryptFailures = 0;
    std::uint64_t tunWrites = 0; ///< Packets forwarded to TUN

    // --- Send path (TUN → encrypt → UDP) ---
    std::uint64_t tunReads = 0; ///< Packets read from TUN
    std::uint64_t packetsEncrypted = 0;
    std::uint64_t packetsSent = 0;          ///< UDP datagrams sent
    std::uint64_t bytesSent = 0;            ///< UDP bytes sent
    std::uint64_t packetsDroppedOnSend = 0; ///< Partial sendmmsg drops
    std::uint64_t sendErrors = 0;
    std::uint64_t txSmallPktFlush = 0; ///< Early drain flushes triggered by small packet mid-batch

    // --- Routing ---
    std::uint64_t routeLookupMisses = 0;

    /** @brief Record a batch receive (call after each recvmmsg). */
    void RecordRecvBatch(std::size_t n, std::size_t batchCapacity)
    {
        batchHist[BatchBin(n)]++;
        if (n == batchCapacity)
            ++batchSaturations;
    }

    /**
     * @brief Compute field-by-field delta between two monotonic snapshots.
     *
     * Safe for uint64_t wraparound (unsigned subtraction).
     * Batch histograms in the delta are zeroed — caller should fill them
     * from a windowed tracker (StatsObserver).
     */
    static DataPathStats Delta(const DataPathStats &now, const DataPathStats &prev)
    {
        DataPathStats d;
        d.packetsReceived = now.packetsReceived - prev.packetsReceived;
        d.bytesReceived = now.bytesReceived - prev.bytesReceived;
        // batchHist left zeroed — filled by StatsObserver::Elapsed()
        d.batchSaturations = now.batchSaturations - prev.batchSaturations;
        d.packetsDecrypted = now.packetsDecrypted - prev.packetsDecrypted;
        d.decryptFailures = now.decryptFailures - prev.decryptFailures;
        d.tunWrites = now.tunWrites - prev.tunWrites;
        d.tunReads = now.tunReads - prev.tunReads;
        d.packetsEncrypted = now.packetsEncrypted - prev.packetsEncrypted;
        d.packetsSent = now.packetsSent - prev.packetsSent;
        d.bytesSent = now.bytesSent - prev.bytesSent;
        d.packetsDroppedOnSend = now.packetsDroppedOnSend - prev.packetsDroppedOnSend;
        d.sendErrors = now.sendErrors - prev.sendErrors;
        d.routeLookupMisses = now.routeLookupMisses - prev.routeLookupMisses;
        d.txSmallPktFlush = now.txSmallPktFlush - prev.txSmallPktFlush;
        return d;
    }
};

// ---------------------------------------------------------------------------
// StatsObserver — compute deltas from monotonic DataPathStats
// ---------------------------------------------------------------------------

/**
 * @brief Observer that independently snapshots DataPathStats and computes
 *        deltas between observations.
 *
 * Each consumer (stats logger, etc.) creates its own observer
 * pointing at the same live counters.  Observers do not interfere with
 * one another and may run on different cadences.
 *
 * Unsigned subtraction naturally handles uint64_t wraparound (would take
 * centuries at 100 Gbps, but the math is correct regardless).
 */
class StatsObserver
{
  public:
    /**
     * @brief Construct an observer referencing live counters.
     * @param source Reference to the monotonic DataPathStats.
     */
    explicit StatsObserver(const DataPathStats &source)
        : source_(source), previous_(source)
    {
    }

    /**
     * @brief Snapshot current counters and return the delta since the last
     *        call (or since construction).
     *
     * batchHist in the returned delta contains per-window histogram counts.
     */
    DataPathStats Elapsed()
    {
        DataPathStats now = source_;
        DataPathStats delta = DataPathStats::Delta(now, previous_);

        // Fill per-window RX histogram from the windowed tracker
        delta.batchHist = windowRxBatchHist_;
        windowRxBatchHist_.fill(0);

        previous_ = now;
        return delta;
    }

    /**
     * @brief Record an RX batch observation for windowed histogram tracking.
     * Must be called from the same thread as RecordRecvBatch (hot path).
     */
    void RecordRxBatchHistogram(std::size_t n)
    {
        windowRxBatchHist_[DataPathStats::BatchBin(n)]++;
    }

  private:
    const DataPathStats &source_; ///< Live monotonic counters (single-thread)
    DataPathStats previous_;      ///< Snapshot taken on last Elapsed() call

    /** Per-window RX batch histogram (reset on each Elapsed() call) */
    std::array<std::uint64_t, DataPathStats::kBatchHistBins> windowRxBatchHist_{};
};

// ---------------------------------------------------------------------------
// StatsRates — computed throughput rates and socket buffer headroom
// ---------------------------------------------------------------------------

struct StatsRates
{
    double rxMbps;  ///< Receive rate in megabits per second
    double txMbps;  ///< Transmit rate in megabits per second
    double rxBufMs; ///< Receive buffer headroom in milliseconds
    double txBufMs; ///< Transmit buffer headroom in milliseconds
};

/**
 * @brief Compute throughput rates (Mbps) and socket buffer headroom (ms)
 *        from a DataPathStats delta.
 *
 * @param delta      Per-interval delta counters.
 * @param elapsedSec Stats interval in seconds.
 * @param rcvBuf     Actual kernel SO_RCVBUF size in bytes.
 * @param sndBuf     Actual kernel SO_SNDBUF size in bytes.
 */
inline StatsRates ComputeStatsRates(const DataPathStats &delta,
                                    double elapsedSec,
                                    int rcvBuf,
                                    int sndBuf)
{
    double rxBps = elapsedSec > 0 ? static_cast<double>(delta.bytesReceived) / elapsedSec : 0;
    double txBps = elapsedSec > 0 ? static_cast<double>(delta.bytesSent) / elapsedSec : 0;

    // Buffer headroom: time until buffer fills at current rate.
    // Zero rate → buffer lasts forever (infinity).
    auto bufMs = [](double bps, int buf) -> double
    {
        if (bps == 0.0)
            return std::numeric_limits<double>::infinity();
        return static_cast<double>(buf) / bps * 1000.0;
    };
    return {
        .rxMbps = rxBps * 8.0 / 1e6,
        .txMbps = txBps * 8.0 / 1e6,
        .rxBufMs = bufMs(rxBps, rcvBuf),
        .txBufMs = bufMs(txBps, sndBuf),
    };
}

/**
 * @brief Format a buffer-headroom value for log output.
 *
 * Returns "---" when the throughput was too low to compute a meaningful
 * estimate (sentinel value -1 from ComputeStatsRates).
 */
inline std::string FormatBufMs(double ms)
{
    if (std::isinf(ms) || ms < 0.0)
        return "---";
    return std::to_string(static_cast<long long>(ms + 0.5));
}

// ---------------------------------------------------------------------------
// FormatBatchHist — format a batch-size histogram for log output
// ---------------------------------------------------------------------------

/**
 * @brief Format a batch histogram array as a compact percentage string.
 *
 * Output:  `{02,05,10,30,40,08,03,02}-17`   (client style, open='{'  close='}')
 *      or  `[02,05,10,30,40,08,03,02]-17`   (server style, open='['  close=']')
 *
 * Returns `"idle"` when the histogram is all-zero.
 *
 * @param hist   Histogram bins (same size as DataPathStats::kBatchHistBins).
 * @param sat    Saturation count appended after the closing bracket.
 * @param open   Opening bracket character (default '{').
 * @param close  Closing bracket character (default '}').
 */
inline std::string FormatBatchHist(
    const std::array<std::uint64_t, DataPathStats::kBatchHistBins> &hist,
    std::uint64_t sat,
    char open = '[',
    char close = ']')
{
    std::uint64_t total = 0;
    for (auto c : hist)
        total += c;
    if (total == 0)
        return "idle";

    std::string s{open};
    for (std::size_t i = 0; i < hist.size(); ++i)
    {
        if (i > 0)
            s += ',';
        auto pct = (hist[i] * 100 + total / 2) / total;
        if (pct < 10)
            s += '0';
        s += std::to_string(pct);
    }
    s += close;
    s += '-';
    s += std::to_string(sat);
    return s;
}

/**
 * @brief Format a 4-bin ring occupancy histogram as a compact percentage string.
 *
 * Bins: [empty, low (1-25%), med (26-75%), high (76-99%)].
 * Returns `"idle"` when no enqueues have been recorded.
 */
inline std::string FormatRingOccHist(
    const std::array<std::uint64_t, DataPathStats::kRingOccBins> &hist)
{
    std::uint64_t total = 0;
    for (auto c : hist)
        total += c;
    if (total == 0)
        return "idle";

    std::string s = "[";
    for (std::size_t i = 0; i < hist.size(); ++i)
    {
        if (i > 0)
            s += ',';
        auto pct = (hist[i] * 100 + total / 2) / total;
        if (pct < 10)
            s += '0';
        s += std::to_string(pct);
    }
    s += ']';
    return s;
}

/**
 * @brief Format an average burst size for log output.
 *
 * Returns `"---"` when no sessions were recorded in the interval.
 */
inline std::string FormatAvgBurst(std::uint64_t total, std::uint64_t count)
{
    if (count == 0)
        return "---";
    return std::to_string((total + count / 2) / count);
}

// ---------------------------------------------------------------------------
// BatchHistWindow — per-thread windowed batch-size histogram (lock-free)
// ---------------------------------------------------------------------------

/**
 * @brief Atomic windowed batch-size histogram for cross-thread stats.
 *
 * One worker thread calls Record() on the hot path (one atomic per batch,
 * not per packet).  The control thread calls SnapshotAndReset() at the
 * stats interval to atomically capture and zero each bin.
 */
struct BatchHistWindow
{
    std::array<std::atomic<std::uint64_t>, DataPathStats::kBatchHistBins> bins{};

    /// Record a batch observation (worker thread, one call per batch).
    void Record(std::size_t n)
    {
        bins[DataPathStats::BatchBin(n)].fetch_add(1, std::memory_order_relaxed);
    }

    /// Atomically read and reset all bins (control thread, once per interval).
    std::array<std::uint64_t, DataPathStats::kBatchHistBins> SnapshotAndReset()
    {
        std::array<std::uint64_t, DataPathStats::kBatchHistBins> result;
        for (std::size_t i = 0; i < bins.size(); ++i)
            result[i] = bins[i].exchange(0, std::memory_order_relaxed);
        return result;
    }
};

// ---------------------------------------------------------------------------
// TxBurstAvgWindow — per-interval average TX burst size (lock-free)
// ---------------------------------------------------------------------------

/**
 * @brief Atomic windowed counter pair for average TX drain-session burst size.
 *
 * Producer calls Record(session_packets) on each EAGAIN boundary.
 * Control thread calls SnapshotAndReset() to get {total_packets, session_count}
 * for the interval and compute the mean.
 */
struct TxBurstAvgWindow
{
    std::atomic<std::uint64_t> total{0};
    std::atomic<std::uint64_t> count{0};

    /// Record one drain session (producer thread).
    void Record(std::size_t n)
    {
        total.fetch_add(n, std::memory_order_relaxed);
        count.fetch_add(1, std::memory_order_relaxed);
    }

    /// Atomically read and reset both counters (control thread, once per interval).
    std::pair<std::uint64_t, std::uint64_t> SnapshotAndReset()
    {
        auto t = total.exchange(0, std::memory_order_relaxed);
        auto c = count.exchange(0, std::memory_order_relaxed);
        return {t, c};
    }
};

// ---------------------------------------------------------------------------
// RingOccHistWindow — per-interval SPSC ring occupancy histogram (lock-free)
// ---------------------------------------------------------------------------

/**
 * @brief Atomic windowed 4-bin ring occupancy histogram.
 *
 * Bins: [0]=empty, [1]=1-25%, [2]=26-75%, [3]=76-99%.
 * Producer calls Record(occupancy, ring_depth) at each partition enqueue.
 * Control thread calls SnapshotAndReset() at the stats interval.
 */
struct RingOccHistWindow
{
    std::array<std::atomic<std::uint64_t>, DataPathStats::kRingOccBins> bins{};

    /// Record one enqueue observation (producer thread).
    void Record(std::size_t occupancy, std::size_t depth)
    {
        bins[OccBin(occupancy, depth)].fetch_add(1, std::memory_order_relaxed);
    }

    /// Atomically read and reset all bins (control thread, once per interval).
    std::array<std::uint64_t, DataPathStats::kRingOccBins> SnapshotAndReset()
    {
        std::array<std::uint64_t, DataPathStats::kRingOccBins> result;
        for (std::size_t i = 0; i < bins.size(); ++i)
            result[i] = bins[i].exchange(0, std::memory_order_relaxed);
        return result;
    }

    /// Map (occupancy, ring_depth) → bin index.
    static unsigned OccBin(std::size_t occ, std::size_t depth)
    {
        if (depth == 0 || occ == 0)
            return 0;
        const auto pct = occ * 100 / depth;
        if (pct <= 25)
            return 1;
        if (pct <= 75)
            return 2;
        return 3;
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_DATA_PATH_STATS_H
