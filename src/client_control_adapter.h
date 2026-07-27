// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_CONTROL_ADAPTER_H
#define CLV_VPN_CLIENT_CONTROL_ADAPTER_H

/**
 * @file client_control_adapter.h
 * @brief Client OpenVPN control-protocol engine.
 *
 * Owns connection flow, TLS handshake, key derivation, PUSH exchange,
 * keepalive, reconnect, TUN configuration, and stats. Transport-specific I/O
 * lives on ChannelT (UDP / TCP / DCO client channels).
 *
 * Method bodies live in client_control_adapter.cpp with explicit instantiation
 * for the three client channel types.
 *
 * @tparam ChannelTpl  ClientUdpChannel / ClientDcoChannel / ClientTcpChannel
 *                     (template template; Adapter is ClientDataAdapter<Self>).
 */

#include "client_data_adapter.h"
#include "data_path_stats.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_channel.h"
#include "openvpn/crypto_context.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/tls_crypt_v2.h"
#include "openvpn/vpn_config.h"
#include "transport/transport.h"

#include <not_null.h>


#include <log_utils.h>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace clv::vpn {


/**
 * @brief Connection state for the VPN client.
 */
enum class VpnClientState
{
    Disconnected,
    Connecting,
    TlsHandshake,
    Authenticating,
    Connected,
    Reconnecting,
    Error
};

const char *VpnClientStateToString(VpnClientState state);

/**
 * @brief Configuration struct passed to ClientControlAdapter::Initialize.
 */
struct ClientControlConfig
{
    asio::io_context &io_context;
    const VpnConfig &config;
    spdlog::logger &logger;
    std::atomic<bool> &running;
};

/**
 * @brief Client control plane — owns ChannelTpl<Adapter> + ClientDataAdapter<Self>.
 *
 * @tparam ChannelTpl  ClientUdp/Dco/TcpChannel template (injected Adapter).
 */
template <template <typename> class ChannelTpl>
class ClientControlPlane
{
  public:
    using Adapter = ClientDataAdapter<ClientControlPlane>;
    using channel_type = ChannelTpl<Adapter>;

    explicit ClientControlPlane(ClientControlConfig cfg);

    // -- Public accessors (used by VpnClient shell) ---------------------------

    asio::io_context &io_context() noexcept;
    VpnClientState GetState() const;
    bool IsConnected() const;
    const VpnConfig &GetConfig() const;
    std::string GetAssignedIp() const;
    std::vector<std::string> GetRoutes() const;
    std::vector<std::string> GetDnsServers() const;
    std::vector<std::string> GetDnsSearchDomains() const;
    DataPathStats GetStats() const;
    std::chrono::seconds GetUptime() const;

    /// App-facing; type-erased (open set of callers).
    using StateCallback = std::function<void(VpnClientState, VpnClientState)>;
    void SetStateCallback(StateCallback cb);

    void TouchLastRx();

    void Connect();
    void Disconnect();

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data);

    channel_type &channel() noexcept { return channel_; }
    const channel_type &channel() const noexcept { return channel_; }
    channel_type &ch() noexcept { return channel_; }
    const channel_type &ch() const noexcept { return channel_; }

    std::chrono::steady_clock::time_point LastTxTime() const
    {
        return channel_.LastTxTime();
    }

  private:
    // -- Connection flow -----------------------------------------------------

    asio::awaitable<void> ConnectionLoop();
    asio::awaitable<void> ReconnectLoop();

    // -- Handshake -----------------------------------------------------------

    asio::awaitable<void> SendHardReset();
    asio::awaitable<void> ProcessServerPacket(std::vector<std::uint8_t> data);
    asio::awaitable<void> HandleControlPacket(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> HandleSoftResetFromServer(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> ClientRekeyLoop(std::uint32_t reneg_seconds, std::uint64_t generation);
    asio::awaitable<void> HandleDataPacket(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> ProcessTlsHandshake();
    asio::awaitable<void> ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext);
    asio::awaitable<void> SendPushRequest();
    asio::awaitable<void> HandlePushReply(const std::string &reply);

    void ApplyNegotiatedNetworkConfig();

    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data);
    asio::awaitable<void> SendRawPacket(std::span<const std::uint8_t> data);

    asio::awaitable<bool> SendV2WkcControl(std::vector<std::uint8_t> serialized,
                                           std::optional<std::uint32_t> counter_override,
                                           std::string_view description);

    void SetState(VpnClientState new_state);
    void StartDataPath();

    asio::awaitable<void> KeepaliveLoop();
    asio::awaitable<void> StatsLoop();
    void LogStats(const DataPathStats &delta, double elapsedSec);

    void InitializeTransport();
    bool LoadTlsCryptKey();
    bool EmplaceTlsCrypt(std::optional<openvpn::TlsCrypt> tc);
    bool InstallV2ClientKey(std::optional<openvpn::TlsCryptV2::ClientKeyData> client_key);
    bool InitializeControlChannel();
    openvpn::TlsCertConfig MakeTlsCertConfig() const;
    std::chrono::steady_clock::time_point LastRxTime() const;

    void DeriveAndInstallKeys();

    // -- State ---------------------------------------------------------------

    not_null<asio::io_context *> io_context_;
    not_null<const VpnConfig *> config_;
    not_null<spdlog::logger *> logger_;
    not_null<std::atomic<bool> *> running_;

    Adapter data_adapter_;
    channel_type channel_;

    VpnClientState state_ = VpnClientState::Disconnected;
    StateCallback state_callback_;
    int reconnect_attempts_ = 0;

    std::optional<transport::TransportHandle> transport_;

    std::uint64_t local_session_id_ = 0;
    std::uint64_t remote_session_id_ = 0;
    std::uint32_t server_peer_id_ = 0;
    std::uint8_t key_id_ = 0;

    std::optional<openvpn::ControlChannel> control_channel_;
    std::optional<openvpn::CryptoContext> crypto_context_;
    std::optional<openvpn::TlsCrypt> tls_crypt_;
    openvpn::TlsCryptReplayState tls_crypt_replay_;
    std::vector<std::uint8_t> tls_crypt_v2_wkc_;
    openvpn::ConfigExchange config_exchange_;

    std::vector<std::uint8_t> client_random_;
    std::vector<std::uint8_t> server_random_;

    DataPathStats stats_;
    std::chrono::steady_clock::time_point connected_at_;

    std::atomic<std::int64_t> last_rx_ns_{0};

    std::optional<asio::steady_timer> stats_timer_;
    std::optional<asio::steady_timer> keepalive_timer_;
    std::optional<asio::steady_timer> handshake_timer_;

    bool rekey_timer_armed_ = false;
    std::uint64_t rekey_generation_ = 0;
    std::chrono::steady_clock::time_point last_server_rekey_at_;
    std::vector<std::string> effective_data_ciphers_;
    std::string negotiated_cipher_;
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_CONTROL_ADAPTER_H
