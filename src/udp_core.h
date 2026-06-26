// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_CORE_H
#define CLV_VPN_UDP_CORE_H

/**
 * @file udp_core.h
 * @brief CRTP engine core for UDP data channels.
 *
 * @tparam Derived     Final CRTP type (e.g. ClientUdpChannel).
 * @tparam PeerPolicy  Policy owning per-peer crypto state and dispatch hooks
 *                     (P2PPolicy or MultiPeerPolicy).
 */

#include "cpu_affinity.h"
#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "udp_worker_thread.h"
#include "udp_engine_types.h"
#include "transport/batch_constants.h"
#include "transport/packet_arena.h"
#include "transport/transport.h"
#include "transport/udp_batch.h"

#include <algorithm>
#include <exception>
#include <memory>
#include <tun/tun_device.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/spdlog.h>

#include <not_null.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <unistd.h>
#include <utility>
#include <vector>

namespace clv::vpn {

// ============================================================================
// UdpCore<Derived, PeerPolicy>
// ============================================================================

template <typename Derived, typename PeerPolicy>
class UdpCore
{
  public:
    struct Config
    {
        std::size_t batch_size = transport::kDefaultBatchSize;
        int cpu_affinity = -2; ///< kAffinityAuto — RX thread CPU pinning.
        int tx_affinity = -2;  ///< kAffinityAuto — TX drain thread CPU pinning.
        /// Max TUN reads per drain cycle. The three stop conditions
        /// (EAGAIN, drain cap, small-packet flush) mean this is a ceiling,
        /// not a typical batch size.
        int tx_drain_depth = 1024;
        /// Max packets per sendmmsg call (0 = same as tx_drain_depth).
        int tx_send_batch = 64;
        /// Payload size (bytes) at which a packet mid-drain triggers an
        /// early flush of the accumulated batch.  0 = disabled.
        int tx_small_pkt_flush = 384;
        /// Total ring/arena size for recvmmsg (0 = same as batch_size).
        /// Larger values reduce syscall overhead at the cost of first-packet
        /// latency within a burst.  The ring wraps slot 0 after filling to end.
        std::size_t max_recv = 0;
        /// Two-pass mini-batch size: decrypt N, then write TUN N, repeat.
        /// 0 = process the entire received count in one pass (original behaviour).
        /// Tune for decrypt-ILP vs TUN write latency trade-off (default: 64).
        std::size_t rx_process_batch = 64;
    };

  protected:
    UdpCore(Config config,
            asio::io_context &control_ctx,
            spdlog::logger &logger)
        : policy_(logger),
          inbound_arena_(std::min(
              config.max_recv == 0 ? config.batch_size : config.max_recv,
              openvpn::ReplayWindow::kBits - 1)),
          rx_scratch_(std::make_unique<transport::BatchScratchpad>()),
          control_ctx_(control_ctx),
          logger_(&logger),
          config_(config)
    {
    }


    ~UdpCore()
    {
        CoreStop();
    }

    UdpCore(const UdpCore &) = delete;
    UdpCore &operator=(const UdpCore &) = delete;

    Derived &derived() noexcept
    {
        return static_cast<Derived &>(*this);
    }
    const Derived &derived() const noexcept
    {
        return static_cast<const Derived &>(*this);
    }

    // -- Lifecycle -----------------------------------------------------------

    void CoreBind(int socket_fd, tun::TunDevice &tun)
    {
        socket_fd_ = socket_fd;
        tun_ = &tun;
    }

    void CoreStart()
    {
        if (running_.exchange(true))
            return;

        rx_thread_ = std::make_unique<UdpWorkerThread>("RX", config_.cpu_affinity, *logger_);
        rx_thread_->Start();
        asio::co_spawn(rx_thread_->context(), RxLoop(), asio::detached);

        tx_thread_ = std::make_unique<UdpWorkerThread>("TX", config_.tx_affinity, *logger_);
        tx_thread_->Start();
        asio::co_spawn(tx_thread_->context(), TxLoop(), asio::detached);

        logger_->info("UdpCore: started (batch_size={}, max_recv={}, process_batch={}, tx_drain_depth={}, rx_arena={}KB)",
                      config_.batch_size,
                      config_.max_recv == 0 ? config_.batch_size : config_.max_recv,
                      config_.rx_process_batch,
                      config_.tx_drain_depth,
                      inbound_arena_.TotalSize() / 1024);
    }

    void CoreStop()
    {
        if (!running_.exchange(false))
            return;

        if (rx_thread_)
        {
            rx_thread_->Stop();
            rx_thread_.reset();
        }

        if (tx_thread_)
        {
            tx_thread_->Stop();
            tx_thread_.reset();
        }

        policy_.Reset();

        logger_->info("UdpCore: stopped");
    }

    // -- Key / Peer (DCO-like API) -------------------------------------------

    void CoreInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                         const openvpn::EncryptionKey &decrypt_key,
                         std::uint8_t key_id)
    {
        // Publish decrypt key to RX thread via atomic double-buffer — no post
        // needed.  ApplyDecryptSnapshot() writes to the inactive slot and
        // release-stores the active index; DecryptInPlace() acquire-loads it
        // on the next packet.  The new key is visible to the RX thread
        // immediately, closing the window where packets with the new key_id
        // arrived before the old asio::post had been drained.
        {
            RxDecryptSnapshot snap;
            snap.decrypt_key = decrypt_key;
            snap.key_id = key_id;
            snap.valid = true;
            policy_.ApplyDecryptSnapshot(snap);
        }

        // Publish encrypt key to TX thread
        if (tx_thread_ && tx_thread_->running())
        {
            asio::post(tx_thread_->context(), [this, encrypt_key, key_id]()
            {
                policy_.ApplyEncryptKey(encrypt_key, key_id);
            });
        }
        else
        {
            policy_.ApplyEncryptKey(encrypt_key, key_id);
        }

        logger_->debug("UdpCore::CoreInstallKeys: key_id={}", key_id);
    }

    void CoreSetPeer(transport::PeerEndpoint peer, openvpn::SessionId session_id)
    {
        if (tx_thread_ && tx_thread_->running())
        {
            asio::post(tx_thread_->context(), [this, peer, session_id]()
            {
                policy_.SetPeer(peer, session_id, socket_fd_);
            });
        }
        else
        {
            policy_.SetPeer(peer, session_id, socket_fd_);
        }

        logger_->debug("UdpCore::CoreSetPeer: session_id={}", session_id.value);
    }

    // -- Stats ---------------------------------------------------------------

    bool CoreRunning() const noexcept
    {
        return running_.load(std::memory_order_relaxed);
    }

    DataPathStats CoreSnapshotStats() const
    {
        return DataPathStats::Merge(rx_counters_, tx_counters_);
    }

    BatchHistWindow &CoreRxBatchWindow()
    {
        return rx_batch_window_;
    }

    TxBurstAvgWindow &CoreTxBurstAvgWindow()
    {
        return tx_burst_avg_window_;
    }

    PeerPolicy &policy() noexcept
    {
        return policy_;
    }
    const PeerPolicy &policy() const noexcept
    {
        return policy_;
    }

    // -- Accessors for mixin use ---------------------------------------------

    asio::io_context &control_ctx() noexcept
    {
        return control_ctx_;
    }
    spdlog::logger &logger() noexcept
    {
        return *logger_;
    }
    int socket_fd() const noexcept
    {
        return socket_fd_;
    }
    tun::TunDevice *tun() const noexcept
    {
        return tun_;
    }

  private:
    // ---- RX coroutine — recvmmsg → decrypt → CRTP dispatch → TUN write -----

    asio::awaitable<void> RxLoop()
    {
        if (socket_fd_ < 0 || !tun_)
            co_return;

        int tunFd = tun_->IsOpen() ? tun_->NativeHandle() : -1;

        // dup'd fd for ASIO epoll on the RX io_context.
        // recvmmsg() still uses the original socket_fd_ (shared with TX sendmmsg).
        int rx_fd = ::dup(socket_fd_);
        if (rx_fd < 0)
        {
            logger_->error("UdpCore::RxLoop: dup() failed: {}", strerror(errno));
            co_return;
        }
        asio::posix::stream_descriptor rx_wait(rx_thread_->context(), rx_fd);

        const auto maxRecv = inbound_arena_.BatchSize(); // arena size (= max_recv or batch_size)
        const auto processBatch = config_.rx_process_batch == 0 ? maxRecv
                                                                : config_.rx_process_batch;

        // Pre-allocate inbound arena slots
        inbound_slots_.resize(maxRecv);
        for (std::size_t i = 0; i < maxRecv; ++i)
        {
            inbound_slots_[i].buf = inbound_arena_.Slot(i);
            inbound_slots_[i].capacity = inbound_arena_.SlotSize();
            inbound_slots_[i].len = 0;
        }

        // Staging buffer for one mini-batch of decrypt results.
        // Sized to processBatch; re-used across iterations with no allocation.
        struct RxDesc
        {
            enum class Action : std::uint8_t
            {
                Drop,
                WriteTun,
                PostControl
            };
            Action action = Action::Drop;
            std::uint8_t *data_ptr = nullptr;
            std::size_t data_len = 0;
            transport::PeerEndpoint sender = {};
        };
        std::vector<RxDesc> proc_buf(processBatch);

        // Circular ring position: next slot index to recv into [0, maxRecv).
        // After filling to the end (ring_pos + count == maxRecv) the next call
        // starts at 0, reusing the same buffer slots (already processed).
        std::size_t ring_pos = 0;

        policy_.OnRxStart();

        logger_->info("UdpCore::RxLoop: circular ring "
                      "(max_recv={}, process_batch={}, arena={}KB, tunFd={})",
                      maxRecv,
                      processBatch,
                      inbound_arena_.TotalSize() / 1024,
                      tunFd);

        while (running_.load(std::memory_order_relaxed))
        {
            try
            {
                // Recv from ring_pos to end of ring in one recvmmsg call.
                const auto recvLimit = maxRecv - ring_pos;
                auto slots_span = std::span<transport::IncomingSlot>(
                    inbound_slots_.data() + ring_pos, recvLimit);

                for (auto &s : slots_span)
                    s.len = 0;

                const auto count = transport::RecvBatch(socket_fd_, slots_span, *rx_scratch_);

                if (count == 0)
                {
                    co_await rx_wait.async_wait(
                        asio::posix::stream_descriptor::wait_read,
                        asio::use_awaitable);
                    continue;
                }

                rx_counters_.RecordRecvBatch(count, recvLimit);
                rx_batch_window_.Record(count);
                policy_.OnPostRecvBatch(count);

                // Process received slots in mini-batches of processBatch.
                // Pass 1: classify + decrypt all n slots into proc_buf[].
                // Pass 2: write TUN / dispatch control for all n slots.
                // Two-pass improves ILP: tight decrypt loop runs hot on cipher
                // state, then tight write loop stays in TUN kernel path.
                std::size_t done = 0;
                while (done < count)
                {
                    const auto n = std::min(processBatch, count - done);
                    const auto base = ring_pos + done;

                    // -- Pass 1: decrypt -----------------------------------------
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        auto &slot = inbound_slots_[base + i];
                        auto &d = proc_buf[i];
                        d.action = RxDesc::Action::Drop;

                        rx_counters_.packetsReceived++;
                        rx_counters_.bytesReceived += slot.len;

                        if (slot.len == 0)
                            continue;

                        derived().OnRxActivity();

                        const auto opcode = openvpn::GetOpcode(slot.buf[0]);

                        if (openvpn::IsDataPacket(opcode) && tunFd >= 0)
                        {
                            auto plaintext = policy_.DecryptInPlace(slot);
                            if (!plaintext.empty())
                            {
                                rx_counters_.packetsDecrypted++;
                                if (!openvpn::IsKeepalivePing(plaintext) && plaintext.size() >= openvpn::IPV4_MIN_HEADER_SIZE)
                                {
                                    d.action = RxDesc::Action::WriteTun;
                                    d.data_ptr = plaintext.data();
                                    d.data_len = plaintext.size();
                                }
                            }
                            else
                            {
                                rx_counters_.decryptFailures++;
                            }
                        }
                        else
                        {
                            d.action = RxDesc::Action::PostControl;
                            d.data_ptr = slot.buf;
                            d.data_len = slot.len;
                            d.sender = slot.sender;
                        }
                    }

                    // -- Pass 2: write TUN / dispatch ----------------------------
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        const auto &d = proc_buf[i];
                        if (d.action == RxDesc::Action::WriteTun)
                        {
                            ::write(tunFd, d.data_ptr, d.data_len);
                            rx_counters_.tunWrites++;
                        }
                        else if (d.action == RxDesc::Action::PostControl)
                        {
                            std::vector<std::uint8_t> data(d.data_ptr, d.data_ptr + d.data_len);
                            derived().OnControlPacket(std::move(data), d.sender);
                        }
                    }

                    done += n;
                }

                // Advance ring position; wrap to 0 when we reach the end.
                ring_pos = (ring_pos + count) % maxRecv;
            }
            catch (const std::exception &e)
            {
                if (running_.load(std::memory_order_relaxed))
                    logger_->error("UdpCore::RxLoop error: {}", e.what());
            }
        }

        policy_.OnRxStop();
        logger_->info("UdpCore::RxLoop stopped");
    }

    // ---- TX coroutine — drain loop: TUN read → encrypt → sendmmsg ----------
    //
    // Slot layout: [TxSlotMeta][kDataV2Overhead bytes][plaintext/ciphertext]
    //
    // Each drain cycle:
    //   1. Fill pass: read up to tx_drain_depth packets from TUN into arena,
    //      stopping early on EAGAIN, small-packet flush trigger, or cap.
    //   2. Encrypt pass: call policy.EncryptSlot() per filled slot.
    //   3. Send pass: TxFlushBuf() in chunks of tx_send_batch.
    //   4. UpdateLastOutbound pass: deduped per Connection* (non-null conns).

    struct TxSlotMeta
    {
        std::size_t payload_len = 0;
        std::size_t wire_len = 0;
        Connection *conn = nullptr;
        bool valid = false;
    };
    static_assert(alignof(TxSlotMeta) <= alignof(std::max_align_t));

    asio::awaitable<void> TxLoop()
    {
        if (!tun_)
            co_return;

        const auto drainDepth = static_cast<std::size_t>(
            config_.tx_drain_depth > 0 ? config_.tx_drain_depth : 256);
        const auto sendBatch = static_cast<std::size_t>(
            config_.tx_send_batch > 0 ? config_.tx_send_batch : drainDepth);
        const auto smallFlush = static_cast<std::size_t>(config_.tx_small_pkt_flush);
        constexpr std::size_t kMeta = sizeof(TxSlotMeta);
        constexpr std::size_t kOff = openvpn::kDataV2Overhead;
        constexpr std::size_t kSlotSz = kMeta + kOff + tun::TunDevice::DEFAULT_MTU;

        // dup'd fd for ASIO epoll.  The original tun fd is used for read().
        int tunFd = tun_->NativeHandle();
        int tx_wait_fd = ::dup(tunFd);
        if (tx_wait_fd < 0)
        {
            logger_->error("UdpCore::TxLoop: dup(tun_fd) failed: {}", strerror(errno));
            co_return;
        }
        asio::posix::stream_descriptor tx_wait(tx_thread_->context(), tx_wait_fd);

        // Arena: drainDepth slots, each kSlotSz bytes.
        transport::PacketArena tx_arena(drainDepth, kSlotSz);
        transport::BatchScratchpad tx_scratch;
        std::vector<transport::SendEntry> send_buf;
        std::vector<Connection *> send_conns;
        send_buf.reserve(drainDepth);
        send_conns.reserve(drainDepth);

        logger_->info("UdpCore::TxLoop: drain_depth={} send_batch={} small_pkt_flush={} arena={}KB",
                      drainDepth,
                      sendBatch,
                      smallFlush,
                      tx_arena.TotalSize() / 1024);

        policy_.OnTxStart();

        while (running_.load(std::memory_order_relaxed))
        {
            try
            {
                // ---- Fill pass: read TUN packets into arena slots ----------
                // Try non-blocking reads first; only suspend if the TUN is empty.
                std::size_t count = 0;
                bool eagain = false;
                for (; count < drainDepth && !eagain; ++count)
                {
                    auto *slot = tx_arena.Slot(count);
                    auto *read_target = slot + kMeta + kOff;
                    auto &meta = *reinterpret_cast<TxSlotMeta *>(slot);
                    meta = TxSlotMeta{};

                    const ssize_t n = ::read(tunFd, read_target, tun::TunDevice::DEFAULT_MTU);
                    if (n <= 0)
                    {
                        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                            eagain = true;
                        break; // stop fill; encrypt what we have
                    }
                    meta.payload_len = static_cast<std::size_t>(n);
                    meta.valid = true;
                    tx_counters_.tunReads++;

                    // Early flush if small packet and we already have >= 1 queued.
                    if (smallFlush > 0 && count >= 1 && meta.payload_len <= smallFlush)
                    {
                        ++count; // include this slot in the batch
                        tx_counters_.txSmallPktFlush++;
                        break;
                    }
                }

                if (count == 0)
                {
                    // TUN is empty — suspend until readable, then retry.
                    co_await tx_wait.async_wait(
                        asio::posix::stream_descriptor::wait_read,
                        asio::use_awaitable);
                    continue;
                }

                if (!policy_.TxReady())
                    continue; // no key yet; packets discarded; loop drains to EAGAIN then waits

                // ---- Encrypt + Send pass (windowed by sendBatch) ----------
                std::size_t total_encrypted = 0;
                std::size_t total_sent = 0;
                for (std::size_t base = 0; base < count; base += sendBatch)
                {
                    const auto window_n = std::min(sendBatch, count - base);
                    send_buf.clear();
                    send_conns.clear();

                    for (std::size_t j = 0; j < window_n; ++j)
                    {
                        const auto i = base + j;
                        auto *slot = tx_arena.Slot(i);
                        auto &meta = *reinterpret_cast<TxSlotMeta *>(slot);
                        if (!meta.valid)
                            continue;

                        auto slot_span = std::span<std::uint8_t>(
                            slot + kMeta, kOff + meta.payload_len);

                        transport::SendEntry entry{};
                        Connection *conn = nullptr;
                        meta.wire_len = policy_.EncryptSlot(slot_span, meta.payload_len, entry, conn);
                        if (meta.wire_len == 0)
                        {
                            tx_counters_.routeLookupMisses++;
                            continue;
                        }
                        meta.conn = conn;
                        tx_counters_.packetsEncrypted++;
                        tx_counters_.bytesSent += meta.wire_len;
                        send_buf.push_back(std::move(entry));
                        send_conns.push_back(conn);
                    }

                    total_encrypted += send_buf.size();
                    if (send_buf.empty())
                        continue;

                    const auto sent = transport::SendBatch(policy_.TxSocketFd(), std::span<const transport::SendEntry>(send_buf), tx_scratch);
                    total_sent += sent;
                    tx_counters_.packetsSent += sent;

                    Connection *prev_conn = nullptr;
                    for (std::size_t i = 0; i < sent; ++i)
                    {
                        auto *c = send_conns[i];
                        if (c && c != prev_conn)
                        {
                            c->UpdateLastOutbound();
                            prev_conn = c;
                        }
                    }

                    if (sent < send_buf.size())
                    {
                        const auto dropped = send_buf.size() - sent;
                        tx_counters_.packetsDroppedOnSend += dropped;
                        tx_counters_.sendErrors++;
                        logger_->warn("UdpCore::TxLoop: partial send: attempted={} sent={} dropped={}",
                                      send_buf.size(),
                                      sent,
                                      dropped);
                    }
                }

                tx_burst_avg_window_.Record(total_encrypted);

                // Notify policy of batch completion (P2P: updates tx_ns_out_).
                if constexpr (requires { policy_.OnBatchSent(total_sent); })
                    policy_.OnBatchSent(total_sent);
            }
            catch (const std::exception &e)
            {
                if (running_.load(std::memory_order_relaxed))
                    logger_->error("UdpCore::TxLoop error: {}", e.what());
            }
        }

        policy_.OnTxStop();
        logger_->info("UdpCore::TxLoop stopped");
    }

    // ---- State -------------------------------------------------------------

    PeerPolicy policy_;

    // Worker threads
    std::unique_ptr<UdpWorkerThread> rx_thread_;
    std::unique_ptr<UdpWorkerThread> tx_thread_;

    // RX state (owned exclusively by RX thread after Start)
    transport::PacketArena inbound_arena_;
    std::vector<transport::IncomingSlot> inbound_slots_;
    std::unique_ptr<transport::BatchScratchpad> rx_scratch_;

    // TX drain-loop state (owned exclusively by TX thread after Start)
    DataPathStats::TxCounters tx_counters_{};

    // Per-thread stats windows
    DataPathStats::RxCounters rx_counters_{};
    BatchHistWindow rx_batch_window_;
    TxBurstAvgWindow tx_burst_avg_window_;

    asio::io_context &control_ctx_;
    clv::not_null<spdlog::logger *> logger_;

    Config config_;
    int socket_fd_ = -1;
    tun::TunDevice *tun_ = nullptr;
    std::atomic<bool> running_{false};
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_CORE_H
