// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TCP_DATA_CHANNEL_H
#define CLV_VPN_TCP_DATA_CHANNEL_H

/**
 * @file tcp_data_channel.h
 * @brief Server-side TCP data channel (TUN-based, stream-framed coroutine path).
 *
 * Owns a dedicated io_context and background thread for all TCP networking:
 * the accept loop, per-client receive loops, and the TUN→TCP transmit loop
 * all run on internal_ctx_ / internal_thread_.
 *
 * Wire I/O uses TcpTransport's stream peel buffer (multi-frame drain after each
 * fill) and length-prefixed TX frames built in-place in the coalesce buffer;
 * RX decrypts a short burst then flushes TUN writes. Not a UDP-style packet arena.
 *
 * Templated on the DataAdapter type for fully static dispatch —
 * no function pointers, no type erasure.  Control packets, disconnect
 * events, and dead-peer notifications dispatch directly to adapter
 * methods that the compiler can inline.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ServerUdpDataAdapter<DataTransport<...>>).
 */

#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "keepalive_loop.h"
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/session_key_install.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "server_keepalive.h"
#include "traffic_policy.h"
#include "transport/batch_constants.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include "tunnel_zone.h"
#include "tunnel_zone_attachment_guard.h"
#include "udp_engine_types.h"

#include <not_null.h>
#include <optional>
#include <qsbr_type.h>
#include <string>
#include "platform/linux/tun/tun_device.h"
#include "platform/linux/tun/tun_setup.h"
#include <net/ipv6_utils.h>
#include <util/byte_packer.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv6 = clv::net::ipv6;

namespace openvpn {
enum class CipherAlgorithm;
enum class HmacAlgorithm;
} // namespace openvpn

/**
 * @brief Server-side TCP data channel — coroutine stream-framed path.
 *
 * @tparam Adapter  DataAdapter CRTP base type.
 */
template <typename Adapter>
class TcpDataChannel
{
  public:
    /**
     * @brief Construct the server TCP data channel.
     * @param host Listen address
     * @param port Listen port
     * @param session_manager Active session table (control-thread use only)
     * @param logger Data-path logger
     * @param rx_counters Shared RX counter storage
     * @param tx_counters Shared TX counter storage
     * @param keepalive_interval PING interval in seconds
     * @param keepalive_timeout Dead-peer timeout in seconds
     * @param running_flag Shared stop flag
     * @param adapter Data→control adapter
     * @param perf Socket buffers + TX/RX coalesce knobs (shared with UDP)
     */
    TcpDataChannel(const std::string &host,
                   std::uint16_t port,
                   SessionManager &session_manager,
                   spdlog::logger &logger,
                   DataPathStats::RxCounters &rx_counters,
                   DataPathStats::TxCounters &tx_counters,
                   int keepalive_interval,
                   int keepalive_timeout,
                   const std::atomic<bool> &running_flag,
                   Adapter &adapter,
                   const VpnConfig::PerformanceConfig &perf = {})
        : internal_ctx_{},
          tcp_listener_(internal_ctx_, host, port),
          session_manager_(session_manager),
          logger_(&logger),
          rx_counters_(rx_counters),
          tx_counters_(tx_counters),
          keepalive_interval_(keepalive_interval > 0 ? keepalive_interval : 10),
          keepalive_timeout_(keepalive_timeout > 0 ? keepalive_timeout : 120),
          running_(running_flag),
          keepalive_timer_(internal_ctx_),
          adapter_(&adapter),
          socket_recv_buffer_(perf.socket_recv_buffer),
          socket_send_buffer_(perf.socket_send_buffer),
          tx_send_batch_(transport::EffectivePositiveCount(perf.tx_send_batch,
                                                           transport::kDefaultTcpSendBatch)),
          tx_small_pkt_flush_(transport::EffectivePositiveCount(
              perf.tx_small_pkt_flush, transport::kDefaultTcpSmallPktFlush)),
          rx_process_batch_(transport::EffectivePositiveCount(
              perf.rx_process_batch, transport::kDefaultTcpRxProcessBatch))
    {
        logger_->info("TCP channel: tx_send_batch={} tx_small_pkt_flush={} rx_process_batch={}",
                      tx_send_batch_,
                      tx_small_pkt_flush_,
                      rx_process_batch_);
    }

    /** @brief Destroy the channel and stop the internal thread. */
    ~TcpDataChannel() = default;

    TcpDataChannel(const TcpDataChannel &) = delete;
    TcpDataChannel &operator=(const TcpDataChannel &) = delete;
    TcpDataChannel(TcpDataChannel &&) = delete;
    TcpDataChannel &operator=(TcpDataChannel &&) = delete;


    /** @brief Internal io_context used for accept and TUN loops. */
    asio::io_context &InternalContext()
    {
        return internal_ctx_;
    }

    /**
     * @brief Wire QSBR publication context before StartDataPath.
     *
     * The TUN and per-client receive loops run on @c internal_thread_, so they
     * must read sessions and routes from published snapshots rather than the
     * live control-plane maps, and removed connections must outlive the
     * snapshot they appear in.
     *
     * @param ctx Data-plane snapshot context owned by the control plane
     */
    void SetDataPlaneContext(DataPlaneContext *ctx)
    {
        data_plane_ = ctx;
    }

    // -- Data plane setup (called from ServerControlBase::ConfigureDataPlane) ---

    /**
     * @brief Create hub TUN and register with the tunnel zone.
     * @return Hub TUN device name
     */
    std::string ConfigureDataPlane(const VpnConfig::ServerConfig &srv,
                                   asio::io_context & /*io_ctx*/,
                                   TunnelZone *zone)
    {
        // TCP channel runs TUN I/O on its own internal io_context.
        tun_device_ = std::make_unique<tun::TunDevice>(internal_ctx_);
        std::string dev = tun::SetupServerTun(*tun_device_, srv, *logger_);
        if (zone && !dev.empty())
            hub_attachment_.Reset(zone, BuildHubAttachmentSpec(srv, dev));
        return dev;
    }

    // ---- Data-plane interface ----

    /**
     * @brief Decrypt a data packet on the control thread and write to TUN.
     * @param session Owning connection
     * @param packet Encrypted OpenVPN data frame
     */
    asio::awaitable<void> ProcessIncomingDataPacket(Connection *session,
                                                    const openvpn::OpenVpnPacket &packet)
    {
        auto plaintext = session->GetCryptoContext().DecryptPacket(packet);

        switch (openvpn::ClassifyDecryptedPayload(plaintext))
        {
        case openvpn::DecryptedPayloadDisposition::Drop:
            if (plaintext.empty())
            {
                rx_counters_.decryptFailures++;
                logger_->warn("DecryptPacket returned empty (decryption failed)");
            }
            co_return;
        case openvpn::DecryptedPayloadDisposition::Keepalive:
            rx_counters_.packetsDecrypted++;
            co_return;
        case openvpn::DecryptedPayloadDisposition::Forward:
            rx_counters_.packetsDecrypted++;
            rx_counters_.tunWrites++;
            {
                tun::IpPacket ip_packet;
                ip_packet.data = std::move(plaintext);
                co_await SendToTun(ip_packet);
            }
            co_return;
        }
    }

    /**
     * @brief Decrypt a datagram in place; return plaintext only for forwardable IP payloads.
     * @param session Owning connection
     * @param datagram Mutable wire buffer
     * @return Plaintext span, or empty for keepalive/drop/failure
     */
    std::span<std::uint8_t> DecryptAndStripInPlace(Connection *session,
                                                   std::span<std::uint8_t> datagram)
    {
        auto plaintext = session->GetCryptoContext().DecryptPacketInPlace(datagram);
        if (openvpn::ClassifyDecryptedPayload(plaintext)
            != openvpn::DecryptedPayloadDisposition::Forward)
            return {};
        return plaintext;
    }

    /** @brief Start accept loop, TUN transmit loop, and internal io_context thread. */
    asio::awaitable<void> StartDataPath()
    {
        if (!adapter_)
        {
            logger_->error("StartDataPath: adapter not bound");
            co_return;
        }

        if (!data_plane_)
        {
            logger_->error("StartDataPath: data-plane context not wired");
            co_return;
        }

        asio::co_spawn(internal_ctx_, TunTransmitLoop(), asio::detached);
        asio::co_spawn(internal_ctx_, AcceptLoop(), asio::detached);

        // Register once for the thread, not once per coroutine: every loop here
        // is multiplexed onto this one thread, so they share its QSBR identity.
        internal_thread_ = std::jthread([this]
        {
            data_plane_->core->register_thread();
            internal_ctx_.run();
            data_plane_->core->unregister_thread();
        });

        logger_->info("TCP data channel started: accept loop + TUN receiver on dedicated thread (port {})",
                      tcp_listener_.LocalPort());
        co_return;
    }

    /**
     * @brief Stop the internal thread and release hub attachment.
     *
     * Joins @c internal_thread_ before returning: the TUN and per-client loops
     * hold Connection pointers from published snapshots, so the control plane
     * must not start destroying sessions while they are still running.
     */
    void StopDataPath()
    {
        hub_attachment_.Release();
        tun_running_ = false;
        tcp_listener_.Close();
        if (tun_device_)
            tun_device_->Close();

        internal_ctx_.stop();
        if (internal_thread_.joinable())
            internal_thread_.join();
    }

    /** @brief No-op; TCP holds no per-peer kernel state. */
    void RemovePeer(Connection * /*session*/)
    {
    }

    /**
     * @brief Derive and install session keys on a connection.
     * @return false on key derivation or install failure
     */
    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        return openvpn::InstallSessionKeys(session,
                                           key_material,
                                           cipher_algo,
                                           hmac_algo,
                                           key_id,
                                           *logger_);
    }

    /** @brief Send an encrypted keepalive ping on a session's TCP transport. */
    asio::awaitable<void> SendKeepAlivePing(Connection *session)
    {
        if (!session || !session->HasTransport())
        {
            logger_->error("SendKeepAlivePing: session is null or has no transport");
            co_return;
        }

        auto peer_id = session->GetWirePeerId();
        if (!peer_id)
            co_return;

        try
        {
            std::vector<std::uint8_t> ping_payload(
                openvpn::KEEPALIVE_PING_PAYLOAD,
                openvpn::KEEPALIVE_PING_PAYLOAD + openvpn::KEEPALIVE_PING_SIZE);

            auto packet_id = session->TryAllocateOutboundPacketId();
            if (!packet_id)
                co_return;
            auto encrypted = session->GetCryptoContext().EncryptPacketWithId(
                ping_payload, *peer_id, *packet_id);

            if (encrypted.empty())
            {
                logger_->error("SendKeepAlivePing: encryption failed");
                co_return;
            }

            co_await session->GetTransport().Send(encrypted);
        }
        catch (const std::exception &e)
        {
            logger_->error("SendKeepAlivePing: {}", e.what());
        }
    }

    /** @brief Run the server keepalive monitor coroutine. */
    asio::awaitable<void> RunKeepaliveMonitor()
    {
        return KeepaliveLoop(
            "TCP",
            running_,
            keepalive_timer_,
            keepalive_interval_,
            keepalive_timeout_,
            *logger_,
            [this]()
        { return CollectKeepaliveSessions(session_manager_); },
            [this](ConnectionKeepaliveView &sv)
        { return SendKeepAlivePing(sv.conn); },
            [this](ConnectionKeepaliveView &sv)
        { adapter_->OnPeerDead(sv.conn->GetSessionId()); });
    }

    /** @brief Cancel the keepalive monitor timer. */
    void StopKeepaliveMonitor()
    {
        keepalive_timer_.cancel();
    }

    /** @brief No-op; TCP has no recvmmsg-style batch_size knob. */
    void SetBatchSize(std::size_t)
    { /* no-op for TCP */
    }
    /** @brief Always 1; TCP has no recvmmsg-style batch_size knob. */
    std::size_t GetBatchSize() const
    {
        return 1;
    }

    /** @brief Merged RX/TX counter snapshot. */
    DataPathStats SnapshotStats() const
    {
        return DataPathStats::Merge(rx_counters_, tx_counters_);
    }

  private:
    /**
     * @brief Published routing snapshots for one lookup.
     *
     * Held only across straight-line code. Every coroutine on
     * @c internal_thread_ shares that thread's QSBR identity, so a snapshot
     * pointer kept across a suspension point could be reclaimed while another
     * coroutine reports a quiescent state.
     */
    struct RouteSnapshots
    {
        const RoutingTableIpv4 *v4;
        const RoutingTableIpv6 *v6;
    };

    RouteSnapshots ReadRouteSnapshots() const
    {
        return RouteSnapshots{
            .v4 = &*data_plane_->routes_v4.read_quiesced(),
            .v6 = &*data_plane_->routes_v6.read_quiesced(),
        };
    }

    asio::awaitable<void> TunTransmitLoop()
    {
        if (!tun_device_)
        {
            logger_->error("TunTransmitLoop: TUN device not created");
            co_return;
        }

        if (!data_plane_)
        {
            logger_->error("TunTransmitLoop: data-plane context not wired");
            co_return;
        }

        logger_->info("TCP TUN→client forwarding started");

        constexpr std::size_t kOff = openvpn::kDataV2Overhead;
        constexpr std::size_t kIpCap = tun::TunDevice::MAX_PACKET_SIZE;
        constexpr std::size_t kOvpnCap = kOff + kIpCap;
        constexpr std::size_t kMaxBatchBytes = 64 * 1024;
        tx_batch_.clear();
        tx_batch_.reserve(kMaxBatchBytes);
        std::array<std::uint8_t, kIpCap> ip_hold{};

        while (running_ && tun_running_)
        {
            // Batch owner is held as a copied transport handle, not a
            // Connection*: the flush below suspends, and snapshot-derived
            // pointers must not survive a suspension point (see TxSnapshot).
            std::optional<transport::TransportHandle> batch_transport;
            std::uint64_t batch_session_id = 0;
            tx_batch_.clear();
            std::size_t batch_frames = 0;

            data_plane_->core->quiescent_state();

            auto slot = transport::BeginTcpTxFrame(tx_batch_, kOvpnCap);
            std::size_t ip_len = 0;
            try
            {
                ip_len = co_await tun_device_->ReadPacketInto(slot.second.subspan(kOff));
            }
            catch (const asio::system_error &e)
            {
                transport::AbortTcpTxFrame(tx_batch_, slot.first);
                if (e.code() == asio::error::operation_aborted)
                    break;
                logger_->error("TUN read error: {}", e.what());
                break;
            }

            for (;;)
            {
                if (ip_len == 0)
                {
                    transport::AbortTcpTxFrame(tx_batch_, slot.first);
                    break;
                }

                auto *ip_data = slot.second.data() + kOff;
                std::optional<std::uint64_t> session_id_opt;
                const std::uint8_t ip_ver = ip_data[0] >> 4;

                {
                    const auto routes = ReadRouteSnapshots();
                    if (ip_ver == 4 && ip_len >= openvpn::IPV4_MIN_HEADER_SIZE)
                    {
                        const auto dst = clv::netcore::read_uint<4>(
                            std::span<const std::uint8_t>(ip_data + 16, 4));
                        session_id_opt = routes.v4->Lookup(dst);
                    }
                    else if (ip_ver == 6 && ip_len >= 40)
                    {
                        ipv6::Ipv6Address dst_v6;
                        std::memcpy(dst_v6.data(), ip_data + 24, 16);
                        session_id_opt = routes.v6->Lookup(dst_v6);
                    }
                }

                // Flush before resolving the session: the flush suspends, and
                // the resolved entry must not outlive that.
                if (session_id_opt && batch_transport && batch_session_id != *session_id_opt)
                {
                    std::memcpy(ip_hold.data(), ip_data, ip_len);
                    transport::AbortTcpTxFrame(tx_batch_, slot.first);
                    try
                    {
                        co_await batch_transport->SendRaw(tx_batch_);
                    }
                    catch (const std::exception &e)
                    {
                        logger_->warn("TUN→TCP: send failed: {}", e.what());
                    }
                    tx_batch_.clear();
                    batch_frames = 0;
                    batch_transport.reset();
                    slot = transport::BeginTcpTxFrame(tx_batch_, kOvpnCap);
                    std::memcpy(slot.second.data() + kOff, ip_hold.data(), ip_len);
                    ip_data = slot.second.data() + kOff;
                }

                bool encrypted = false;
                if (session_id_opt)
                {
                    openvpn::SessionId session_id{*session_id_opt};
                    const auto &snap_sessions = *data_plane_->sessions.read_quiesced();
                    const auto *entry = snap_sessions.Find(session_id);
                    Connection *session = entry ? entry->conn : nullptr;
                    if (session && session->HasTransport())
                    {
                        if (auto packet_id = session->TryAllocateOutboundPacketId())
                        {
                            const auto wire_len = session->GetCryptoContext().EncryptPacketInPlaceWithId(
                                slot.second, ip_len, entry->peer_id, *packet_id);
                            if (wire_len == 0)
                            {
                                logger_->warn("TUN→TCP: encryption failed for session {}",
                                              session_id);
                            }
                            else
                            {
                                transport::FinishTcpTxFrame(tx_batch_, slot.first, wire_len);
                                batch_transport = session->GetTransport();
                                batch_session_id = session_id.value;
                                encrypted = true;
                                ++batch_frames;
                                tx_counters_.tunReads++;
                                tx_counters_.packetsSent++;
                                tx_counters_.bytesSent += wire_len;
                                session->UpdateLastOutbound();
                            }
                        }
                    }
                }

                if (!encrypted)
                    transport::AbortTcpTxFrame(tx_batch_, slot.first);

                if ((tx_small_pkt_flush_ > 0 && ip_len < tx_small_pkt_flush_)
                    || batch_frames >= tx_send_batch_ || tx_batch_.size() >= kMaxBatchBytes)
                    break;

                slot = transport::BeginTcpTxFrame(tx_batch_, kOvpnCap);
                try
                {
                    ip_len = tun_device_->TryReadPacketInto(slot.second.subspan(kOff));
                }
                catch (const std::exception &e)
                {
                    transport::AbortTcpTxFrame(tx_batch_, slot.first);
                    logger_->error("TUN read error: {}", e.what());
                    ip_len = 0;
                    break;
                }
            }

            if (!tx_batch_.empty() && batch_transport)
            {
                try
                {
                    co_await batch_transport->SendRaw(tx_batch_);
                }
                catch (const std::exception &e)
                {
                    logger_->warn("TUN→TCP: send failed: {}", e.what());
                }
                tx_batch_.clear();
            }
        }

        logger_->info("TCP TUN→client forwarding stopped");
    }

    asio::awaitable<void> AcceptLoop()
    {
        logger_->info("TCP accept loop started on port {}", tcp_listener_.LocalPort());

        while (running_ && tun_running_)
        {
            try
            {
                auto tcpTransport = co_await tcp_listener_.AcceptNext();
                tcpTransport.ApplySocketBuffers(socket_recv_buffer_, socket_send_buffer_, *logger_);
                auto peer = tcpTransport.GetPeer();
                logger_->info("Accepted TCP connection from {}:{}",
                              peer.addr.to_string(),
                              peer.port);

                asio::co_spawn(internal_ctx_,
                               ClientReceiveLoop(std::move(tcpTransport)),
                               asio::detached);
            }
            catch (const std::exception &e)
            {
                if (running_ && tun_running_)
                    logger_->error("TCP accept error: {}", e.what());
            }
        }
    }

    // Demux like UDP/DCO: data opcodes with installed session crypto decrypt +
    // TUN on internal_ctx_; control (or pre-key data) → OnControlPacket only.
    // After each socket fill, drain every complete frame already in the link
    // buffer before awaiting the next read.
    asio::awaitable<void> ClientReceiveLoop(transport::TcpTransport tcpTransport)
    {
        auto peer = tcpTransport.GetPeer();
        logger_->debug("TCP client receive loop started for {}:{}",
                       peer.addr.to_string(),
                       peer.port);

        if (!data_plane_)
        {
            logger_->error("ClientReceiveLoop: data-plane context not wired");
            co_return;
        }

        bool disconnected = false;
        const std::size_t max_tun_burst = rx_process_batch_ > 0 ? rx_process_batch_ : std::numeric_limits<std::size_t>::max();
        // Local: concurrent receive loops must not share pending plaintext spans.
        std::vector<std::span<const std::uint8_t>> tun_pending;
        tun_pending.reserve(rx_process_batch_ > 0 ? rx_process_batch_ : 32);

        while (running_ && tun_running_ && !disconnected)
        {
            try
            {
                auto data = co_await tcpTransport.ReceiveInPlace();
                if (data.empty())
                {
                    logger_->info("TCP client disconnected (empty read): {}:{}",
                                  peer.addr.to_string(),
                                  peer.port);
                    break;
                }

                data_plane_->core->quiescent_state();

                for (;;)
                {
                    const auto opcode = openvpn::GetOpcode(data[0]);
                    if (openvpn::IsDataPacket(opcode))
                    {
                        // Snapshot-derived pointers live only inside this
                        // non-suspending block. A TCP connection keeps one
                        // endpoint for its lifetime, so by_endpoint is an exact
                        // demux here (no float).
                        bool keyed = false;
                        std::span<std::uint8_t> plaintext;
                        {
                            const auto &snap = *data_plane_->sessions_rx.read_quiesced();
                            const auto *entry = snap.FindByEndpoint(peer);
                            if (entry && entry->conn)
                            {
                                keyed = true;
                                entry->conn->UpdateLastActivity();
                                plaintext = entry->conn->GetCryptoContext().DecryptPacketInPlace(data);
                            }
                        }

                        if (keyed)
                        {
                            if (plaintext.empty())
                            {
                                rx_counters_.decryptFailures++;
                            }
                            else
                            {
                                rx_counters_.packetsDecrypted++;
                                switch (openvpn::ClassifyDecryptedPayload(plaintext))
                                {
                                case openvpn::DecryptedPayloadDisposition::Keepalive:
                                case openvpn::DecryptedPayloadDisposition::Drop:
                                    break;
                                case openvpn::DecryptedPayloadDisposition::Forward:
                                    // Plaintext aliases the link buffer until the next fill.
                                    tun_pending.push_back(plaintext);
                                    if ((tx_small_pkt_flush_ > 0
                                         && plaintext.size() < tx_small_pkt_flush_)
                                        || tun_pending.size() >= max_tun_burst)
                                    {
                                        if (!co_await FlushPendingTun(tun_pending))
                                            disconnected = true;
                                    }
                                    break;
                                }
                            }

                            if (disconnected)
                                break;

                            if (auto next = tcpTransport.TryPeelInPlace())
                            {
                                data = *next;
                                if (data.empty())
                                    disconnected = true;
                                else
                                    continue;
                            }
                            break;
                        }
                    }

                    if (!co_await FlushPendingTun(tun_pending))
                    {
                        disconnected = true;
                        break;
                    }

                    // Control (or pre-key data) needs an owning buffer for the
                    // control-plane post.
                    adapter_->OnControlPacket(std::vector<std::uint8_t>(data.begin(), data.end()),
                                              peer,
                                              transport::TransportHandle(tcpTransport));

                    if (auto next = tcpTransport.TryPeelInPlace())
                    {
                        data = *next;
                        if (data.empty())
                            disconnected = true;
                        else
                            continue;
                    }
                    break;
                }

                if (!co_await FlushPendingTun(tun_pending))
                    disconnected = true;
            }
            catch (const asio::system_error &e)
            {
                if (e.code() == asio::error::eof || e.code() == asio::error::connection_reset)
                {
                    logger_->info("TCP client disconnected: {}:{} ({})",
                                  peer.addr.to_string(),
                                  peer.port,
                                  e.what());
                }
                else if (running_ && tun_running_)
                {
                    logger_->error("TCP receive error from {}:{}: {}",
                                   peer.addr.to_string(),
                                   peer.port,
                                   e.what());
                }
                break;
            }
            catch (const std::exception &e)
            {
                if (running_ && tun_running_)
                {
                    logger_->error("TCP receive error from {}:{}: {}",
                                   peer.addr.to_string(),
                                   peer.port,
                                   e.what());
                }
                break;
            }
        }

        adapter_->OnDisconnect(peer);
    }

    /** @brief Write queued plaintext spans to TUN; clears @p pending. @return false on write failure. */
    asio::awaitable<bool> FlushPendingTun(std::vector<std::span<const std::uint8_t>> &pending)
    {
        for (auto plaintext : pending)
        {
            try
            {
                co_await tun_device_->WritePacket(plaintext);
                rx_counters_.tunWrites++;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error writing to TUN: {}", e.what());
                pending.clear();
                co_return false;
            }
        }
        pending.clear();
        co_return true;
    }

    asio::awaitable<void> SendToTun(std::span<const std::uint8_t> packet)
    {
        try
        {
            co_await tun_device_->WritePacket(packet);
        }
        catch (const std::exception &e)
        {
            logger_->error("Error writing to TUN: {}", e.what());
        }
    }

    asio::awaitable<void> SendToTun(const tun::IpPacket &packet)
    {
        co_await SendToTun(std::span<const std::uint8_t>(packet.data));
    }

    asio::io_context internal_ctx_;
    transport::TcpListener tcp_listener_;
    std::jthread internal_thread_;

    std::unique_ptr<tun::TunDevice> tun_device_;
    TunnelZoneAttachmentGuard hub_attachment_;
    /// Control-thread only (keepalive collection); the data path uses snapshots.
    SessionManager &session_manager_;
    clv::not_null<spdlog::logger *> logger_;
    DataPathStats::RxCounters &rx_counters_;
    DataPathStats::TxCounters &tx_counters_;
    std::chrono::seconds keepalive_interval_;
    std::chrono::seconds keepalive_timeout_;
    const std::atomic<bool> &running_;
    bool tun_running_ = true;
    asio::steady_timer keepalive_timer_;

    Adapter *adapter_;
    DataPlaneContext *data_plane_ = nullptr;
    int socket_recv_buffer_ = 0;
    int socket_send_buffer_ = 0;
    std::size_t tx_send_batch_ = transport::kDefaultTcpSendBatch;
    std::size_t tx_small_pkt_flush_ = transport::kDefaultTcpSmallPktFlush;
    std::size_t rx_process_batch_ = transport::kDefaultTcpRxProcessBatch;
    std::vector<std::uint8_t> tx_batch_;
};

} // namespace clv::vpn

#endif // CLV_VPN_TCP_DATA_CHANNEL_H
