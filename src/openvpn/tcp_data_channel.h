// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TCP_DATA_CHANNEL_H
#define CLV_VPN_TCP_DATA_CHANNEL_H

/**
 * @file tcp_data_channel.h
 * @brief Server-side TCP data channel (TUN-based, single-packet coroutine path).
 *
 * Owns a dedicated io_context and background thread for all TCP networking:
 * the accept loop, per-client receive loops, and the TUN→TCP transmit loop
 * all run on internal_ctx_ / internal_thread_.
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
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "transport/listener.h"
#include "transport/transport.h"

#include <not_null.h>
#include <optional>
#include <string>
#include "platform/linux/tun/tun_device.h"
#include "platform/linux/tun/tun_setup.h"
#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>
#include <util/byte_packer.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

namespace openvpn {
enum class CipherAlgorithm;
enum class HmacAlgorithm;
} // namespace openvpn

/**
 * @brief Server-side TCP data channel — coroutine, single-packet path.
 *
 * @tparam Adapter  DataAdapter CRTP base type.
 */
template <typename Adapter>
class TcpDataChannel
{
  public:
    TcpDataChannel(const std::string &host,
                   std::uint16_t port,
                   RoutingTableIpv4 &routing_table,
                   RoutingTableIpv6 &routing_table_v6,
                   SessionManager &session_manager,
                   spdlog::logger &logger,
                   DataPathStats::RxCounters &rx_counters,
                   DataPathStats::TxCounters &tx_counters,
                   int keepalive_interval,
                   int keepalive_timeout,
                   const std::atomic<bool> &running_flag)
        : internal_ctx_{},
          tcp_listener_(internal_ctx_, host, port),
          routing_table_(routing_table),
          routing_table_v6_(routing_table_v6),
          session_manager_(session_manager),
          logger_(&logger),
          rx_counters_(rx_counters),
          tx_counters_(tx_counters),
          keepalive_interval_(keepalive_interval > 0 ? keepalive_interval : 10),
          keepalive_timeout_(keepalive_timeout > 0 ? keepalive_timeout : 120),
          running_(running_flag),
          keepalive_timer_(internal_ctx_)
    {
    }

    ~TcpDataChannel() = default;

    TcpDataChannel(const TcpDataChannel &) = delete;
    TcpDataChannel &operator=(const TcpDataChannel &) = delete;
    TcpDataChannel(TcpDataChannel &&) = delete;
    TcpDataChannel &operator=(TcpDataChannel &&) = delete;

    // -- Static adapter binding (called by DataTransport after construction) --

    void SetAdapter(Adapter &adapter)
    {
        adapter_ = &adapter;
    }

    asio::io_context &InternalContext()
    {
        return internal_ctx_;
    }

    // -- Data plane setup (called from ServerControlBase::ConfigureDataPlane) ---

    std::string ConfigureDataPlane(const VpnConfig::ServerConfig &srv,
                                   asio::io_context & /*io_ctx*/)
    {
        // TCP channel runs TUN I/O on its own internal io_context.
        tun_device_ = std::make_unique<tun::TunDevice>(internal_ctx_);
        return tun::SetupServerTun(*tun_device_, srv, *logger_);
    }

    // ---- Data-plane interface ----

    asio::awaitable<void> ProcessIncomingDataPacket(Connection *session,
                                                    const openvpn::OpenVpnPacket &packet)
    {
        auto plaintext = session->GetCryptoContext().DecryptPacket(packet);

        logger_->debug("DecryptPacket returned {} bytes", plaintext.size());

        if (!plaintext.empty())
        {
            rx_counters_.packetsDecrypted++;

            if (openvpn::IsKeepalivePing(plaintext))
            {
                logger_->debug("Received OpenVPN keepalive ping from client");
                co_return;
            }

            if (plaintext.size() < openvpn::IPV4_MIN_HEADER_SIZE)
            {
                logger_->debug("Ignoring packet too small to be valid IP (size={})", plaintext.size());
            }
            else
            {
                logger_->debug("Forwarding {} decrypted bytes to TUN device", plaintext.size());
                rx_counters_.tunWrites++;
                tun::IpPacket ip_packet;
                ip_packet.data = std::move(plaintext);
                co_await SendToTun(ip_packet);
            }
        }
        else
        {
            rx_counters_.decryptFailures++;
            logger_->warn("DecryptPacket returned empty (decryption failed)");
        }
    }

    std::span<std::uint8_t> DecryptAndStripInPlace(Connection * /*session*/,
                                                   std::span<std::uint8_t> /*datagram*/)
    {
        return {};
    }

    asio::awaitable<void> StartDataPath()
    {
        if (!adapter_)
        {
            logger_->error("StartDataPath: SetAdapter not called");
            co_return;
        }

        asio::co_spawn(internal_ctx_, TunTransmitLoop(), asio::detached);
        asio::co_spawn(internal_ctx_, AcceptLoop(), asio::detached);

        internal_thread_ = std::jthread([this]
        {
            internal_ctx_.run();
        });

        logger_->info("TCP data channel started: accept loop + TUN receiver on dedicated thread (port {})",
                      tcp_listener_.LocalPort());
        co_return;
    }

    void StopDataPath()
    {
        tun_running_ = false;
        tcp_listener_.Close();
        if (tun_device_)
            tun_device_->Close();
    }

    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        bool keys_installed = openvpn::KeyDerivation::InstallKeys(
            session->GetCryptoContext(),
            key_material,
            cipher_algo,
            hmac_algo,
            key_id);

        if (keys_installed)
        {
            logger_->info("Data channel session keys installed successfully (key_id={})", key_id);
            session->GetCryptoContext().SetCurrentKeyId(key_id);
        }
        else
        {
            logger_->error("Failed to install data channel session keys");
        }

        return keys_installed;
    }

    asio::awaitable<void> SendKeepAlivePing(Connection *session)
    {
        if (!session || !session->HasTransport())
        {
            logger_->error("SendKeepAlivePing: session is null or has no transport");
            co_return;
        }

        try
        {
            std::vector<std::uint8_t> ping_payload(
                openvpn::KEEPALIVE_PING_PAYLOAD,
                openvpn::KEEPALIVE_PING_PAYLOAD + openvpn::KEEPALIVE_PING_SIZE);

            auto packet_id = session->TryAllocateOutboundPacketId();
            if (!packet_id)
                co_return;
            auto encrypted = session->GetCryptoContext().EncryptPacketWithId(
                ping_payload, session->GetSessionId(), *packet_id);

            if (encrypted.empty())
            {
                logger_->error("SendKeepAlivePing: encryption failed");
                co_return;
            }

            co_await session->GetTransport().Send(encrypted);
            logger_->debug("SendKeepAlivePing: sent {} encrypted bytes", encrypted.size());
        }
        catch (const std::exception &e)
        {
            logger_->error("SendKeepAlivePing: {}", e.what());
        }
    }

    asio::awaitable<void> RunKeepaliveMonitor()
    {
        using tp = std::chrono::steady_clock::time_point;
        struct SessionView
        {
            Connection *conn;
            bool HasValidKeys() const
            {
                return conn->GetCryptoContext().HasValidKeys();
            }
            tp GetLastActivity() const
            {
                return conn->GetLastActivity();
            }
            tp GetLastOutbound() const
            {
                return conn->GetLastOutbound();
            }
            void UpdateLastOutbound()
            {
                conn->UpdateLastOutbound();
            }
        };

        return KeepaliveLoop(
            "TCP",
            running_,
            keepalive_timer_,
            keepalive_interval_,
            keepalive_timeout_,
            *logger_,
            [this]()
        {
            std::vector<SessionView> result;
            for (auto id : session_manager_.GetAllSessionIds())
                if (auto *s = session_manager_.FindSession(id))
                    result.push_back(SessionView{s});
            return result;
        },
            [this](SessionView &sv)
        { return SendKeepAlivePing(sv.conn); },
            [this](SessionView &sv)
        { adapter_->OnPeerDead(sv.conn->GetSessionId()); });
    }

    void StopKeepaliveMonitor()
    {
        keepalive_timer_.cancel();
    }

    void SetBatchSize(std::size_t)
    { /* no-op for TCP */
    }
    std::size_t GetBatchSize() const
    {
        return 1;
    }

    DataPathStats SnapshotStats() const
    {
        return DataPathStats::Merge(rx_counters_, tx_counters_);
    }

  private:
    asio::awaitable<void> TunTransmitLoop()
    {
        if (!tun_device_)
        {
            logger_->error("TunTransmitLoop: TUN device not created");
            co_return;
        }

        logger_->info("TCP TUN→client forwarding started");

        while (running_ && tun_running_)
        {
            tun::IpPacket ip_packet;
            try
            {
                ip_packet = co_await tun_device_->ReadPacket();
            }
            catch (const asio::system_error &e)
            {
                if (e.code() == asio::error::operation_aborted)
                    break;
                logger_->error("TUN read error: {}", e.what());
                break;
            }

            if (ip_packet.data.empty())
                continue;

            auto *ip_data = ip_packet.data.data();
            const std::size_t ip_len = ip_packet.data.size();

            std::optional<std::uint64_t> session_id_opt;
            const std::uint8_t ip_ver = ip_data[0] >> 4;

            if (ip_ver == 4 && ip_len >= openvpn::IPV4_MIN_HEADER_SIZE)
            {
                const auto dst = clv::netcore::read_uint<4>(
                    std::span<const std::uint8_t>(ip_data + 16, 4));
                session_id_opt = routing_table_.Lookup(dst);
            }
            else if (ip_ver == 6 && ip_len >= 40)
            {
                ipv6::Ipv6Address dst_v6;
                std::memcpy(dst_v6.data(), ip_data + 24, 16);
                session_id_opt = routing_table_v6_.Lookup(dst_v6);
            }
            else
            {
                continue;
            }

            if (!session_id_opt)
            {
                logger_->debug("TUN→TCP: no route for packet (ip_ver={})", ip_ver);
                continue;
            }

            openvpn::SessionId session_id{*session_id_opt};
            Connection *session = session_manager_.FindSession(session_id);
            if (!session || !session->HasTransport())
            {
                logger_->debug("TUN→TCP: session {} not found or has no transport", session_id);
                continue;
            }

            if (!session->GetCryptoContext().HasValidKeys())
            {
                logger_->debug("TUN→TCP: session {} has no valid data channel keys", session_id);
                continue;
            }

            auto packet_id = session->TryAllocateOutboundPacketId();
            if (!packet_id)
                continue;
            auto encrypted = session->GetCryptoContext().EncryptPacketWithId(
                std::span<const std::uint8_t>(ip_packet.data), session_id, *packet_id);

            if (encrypted.empty())
            {
                logger_->warn("TUN→TCP: encryption failed for session {}", session_id);
                continue;
            }

            try
            {
                co_await session->GetTransport().Send(encrypted);
                tx_counters_.tunReads++;
                tx_counters_.packetsSent++;
                tx_counters_.bytesSent += encrypted.size();
                session->UpdateLastOutbound();
            }
            catch (const std::exception &e)
            {
                logger_->warn("TUN→TCP: send failed for session {}: {}", session_id, e.what());
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

    asio::awaitable<void> ClientReceiveLoop(transport::TcpTransport tcpTransport)
    {
        auto peer = tcpTransport.GetPeer();
        logger_->debug("TCP client receive loop started for {}:{}",
                       peer.addr.to_string(),
                       peer.port);

        while (running_ && tun_running_)
        {
            try
            {
                auto data = co_await tcpTransport.Receive();
                if (data.empty())
                {
                    logger_->info("TCP client disconnected (empty read): {}:{}",
                                  peer.addr.to_string(),
                                  peer.port);
                    break;
                }

                logger_->debug("Received TCP packet: {} bytes from {}:{}",
                               data.size(),
                               peer.addr.to_string(),
                               peer.port);

                adapter_->OnControlPacket(std::move(data),
                                          peer,
                                          transport::TransportHandle(tcpTransport));
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

    asio::awaitable<void> SendToTun(const tun::IpPacket &packet)
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

    asio::io_context internal_ctx_;
    transport::TcpListener tcp_listener_;
    std::jthread internal_thread_;

    std::unique_ptr<tun::TunDevice> tun_device_;
    RoutingTableIpv4 &routing_table_;
    RoutingTableIpv6 &routing_table_v6_;
    SessionManager &session_manager_;
    clv::not_null<spdlog::logger *> logger_;
    DataPathStats::RxCounters &rx_counters_;
    DataPathStats::TxCounters &tx_counters_;
    std::chrono::seconds keepalive_interval_;
    std::chrono::seconds keepalive_timeout_;
    const std::atomic<bool> &running_;
    bool tun_running_ = true;
    asio::steady_timer keepalive_timer_;

    Adapter *adapter_ = nullptr;
};

} // namespace clv::vpn

#endif // CLV_VPN_TCP_DATA_CHANNEL_H
