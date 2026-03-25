// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DATA_PATH_STATS_H
#define CLV_VPN_DATA_PATH_STATS_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace clv::vpn {

/**
 * @brief Monotonic counters for the userspace data path.
 *
 * All fields are plain uint64_t — safe because the VPN server runs on a
 * single io_context thread.  Counters only increase (never reset).
 * Consumers that need periodic deltas use StatsObserver.
 */
struct DataPathStats
{
    // --- Batch histogram (linear bins for recvmmsg batch sizes) ---
    // 8 bins × 512 packets: [0]=0-511  [1]=512-1023  [2]=1024-1535  [3]=1536-2047
    //                        [4]=2048-2559  [5]=2560-3071  [6]=3072-3583  [7]=3584-4095
    static constexpr std::size_t kBatchHistBins = 8;
    static constexpr std::size_t kBinWidth = 512;

    /** Compute histogram bin index for a batch size (linear, width=512). */
    static unsigned BatchBin(std::size_t n)
    {
        return static_cast<unsigned>(
            std::min(n / kBinWidth, kBatchHistBins - 1));
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
    std::uint64_t tunReads = 0;                              ///< Packets read from TUN
    std::array<std::uint64_t, kBatchHistBins> txBatchHist{}; ///< Per-bin TUN read batch counts
    std::uint64_t txBatchSaturations = 0;                    ///< readv returned exactly batchSize
    std::uint64_t packetsEncrypted = 0;
    std::uint64_t packetsSent = 0; ///< UDP datagrams sent
    std::uint64_t bytesSent = 0;   ///< UDP bytes sent
    std::uint64_t sendErrors = 0;

    // --- Routing ---
    std::uint64_t routeLookupMisses = 0;

    /** @brief Record a batch receive (call after each recvmmsg). */
    void RecordRecvBatch(std::size_t n, std::size_t batchCapacity)
    {
        batchHist[BatchBin(n)]++;
        if (n == batchCapacity)
            ++batchSaturations;
    }

    /** @brief Record a TUN read batch (call after each readv from TUN). */
    void RecordTunReadBatch(std::size_t n, std::size_t batchCapacity)
    {
        txBatchHist[BatchBin(n)]++;
        if (n == batchCapacity)
            ++txBatchSaturations;
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
        // batchHist / txBatchHist left zeroed — filled by StatsObserver::Elapsed()
        d.batchSaturations = now.batchSaturations - prev.batchSaturations;
        d.packetsDecrypted = now.packetsDecrypted - prev.packetsDecrypted;
        d.decryptFailures = now.decryptFailures - prev.decryptFailures;
        d.tunWrites = now.tunWrites - prev.tunWrites;
        d.tunReads = now.tunReads - prev.tunReads;
        d.txBatchSaturations = now.txBatchSaturations - prev.txBatchSaturations;
        d.packetsEncrypted = now.packetsEncrypted - prev.packetsEncrypted;
        d.packetsSent = now.packetsSent - prev.packetsSent;
        d.bytesSent = now.bytesSent - prev.bytesSent;
        d.sendErrors = now.sendErrors - prev.sendErrors;
        d.routeLookupMisses = now.routeLookupMisses - prev.routeLookupMisses;
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
     * batchHist / txBatchHist in the returned delta contain per-window histogram counts.
     */
    DataPathStats Elapsed()
    {
        DataPathStats now = source_;
        DataPathStats delta = DataPathStats::Delta(now, previous_);

        // Fill per-window histograms from the windowed trackers
        delta.batchHist = windowRxBatchHist_;
        delta.txBatchHist = windowTxBatchHist_;
        windowRxBatchHist_.fill(0);
        windowTxBatchHist_.fill(0);

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

    /**
     * @brief Record a TX (TUN read) batch observation for windowed histogram tracking.
     * Must be called from the same thread as RecordTunReadBatch (hot path).
     */
    void RecordTxBatchHistogram(std::size_t n)
    {
        windowTxBatchHist_[DataPathStats::BatchBin(n)]++;
    }

  private:
    const DataPathStats &source_; ///< Live monotonic counters (single-thread)
    DataPathStats previous_;      ///< Snapshot taken on last Elapsed() call

    /** Per-window RX batch histogram (reset on each Elapsed() call) */
    std::array<std::uint64_t, DataPathStats::kBatchHistBins> windowRxBatchHist_{};
    /** Per-window TX batch histogram (reset on each Elapsed() call) */
    std::array<std::uint64_t, DataPathStats::kBatchHistBins> windowTxBatchHist_{};
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
    return {
        .rxMbps = rxBps * 8.0 / 1e6,
        .txMbps = txBps * 8.0 / 1e6,
        .rxBufMs = rxBps > 0 ? static_cast<double>(rcvBuf) / rxBps * 1000.0
                             : std::numeric_limits<double>::infinity(),
        .txBufMs = txBps > 0 ? static_cast<double>(sndBuf) / txBps * 1000.0
                             : std::numeric_limits<double>::infinity(),
    };
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

} // namespace clv::vpn

#endif // CLV_VPN_DATA_PATH_STATS_H
