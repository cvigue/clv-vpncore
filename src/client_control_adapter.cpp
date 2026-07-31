// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "client_control_adapter.h"
#include "data_path_stats.h"
#include "keepalive_loop.h"
#include "openvpn/config_exchange.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/psid_cookie.h"
#include "openvpn/push_exchange_helpers.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/tls_crypt_v2.h"
#include "openvpn/vpn_config.h"
#include "transport/connector.h"
#include "transport/transport.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <openssl/rand.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

// =============================================================================
// ClientControlAdapter — out-of-line member function definitions
// =============================================================================

template <template <typename> class ChannelTpl>
asio::io_context &ClientControlPlane<ChannelTpl>::io_context() noexcept
{
    return *io_context_;
}

template <template <typename> class ChannelTpl>
VpnClientState ClientControlPlane<ChannelTpl>::GetState() const
{
    return state_;
}

template <template <typename> class ChannelTpl>
bool ClientControlPlane<ChannelTpl>::IsConnected() const
{
    return state_ == VpnClientState::Connected;
}

template <template <typename> class ChannelTpl>
const VpnConfig &ClientControlPlane<ChannelTpl>::GetConfig() const
{
    return *config_;
}

template <template <typename> class ChannelTpl>
std::string ClientControlPlane<ChannelTpl>::GetAssignedIp() const
{
    return config_exchange_.GetNegotiatedConfig().ifconfig.first;
}

template <template <typename> class ChannelTpl>
std::vector<std::string> ClientControlPlane<ChannelTpl>::GetRoutes() const
{
    std::vector<std::string> result;
    for (const auto &[network, gw, metric] : config_exchange_.GetNegotiatedConfig().routes)
        result.push_back(network);
    return result;
}

template <template <typename> class ChannelTpl>
std::vector<std::string> ClientControlPlane<ChannelTpl>::GetDnsServers() const
{
    const auto &cfg = config_exchange_.GetNegotiatedConfig();

    // Prefer structured dns_servers (IV_PROTO_DNS_OPTION_V2 path) when present.
    if (!cfg.dns_servers.empty())
    {
        std::vector<std::string> result;
        for (const auto &entry : cfg.dns_servers)
            for (const auto &addr : entry.addresses)
                result.push_back(addr);
        return result;
    }

    // Fall back to legacy dhcp-option DNS entries.
    std::vector<std::string> result;
    for (const auto &[type, value] : cfg.dhcp_options)
        if (type == "DNS")
            result.push_back(value);
    return result;
}

template <template <typename> class ChannelTpl>
std::vector<std::string> ClientControlPlane<ChannelTpl>::GetDnsSearchDomains() const
{
    return config_exchange_.GetNegotiatedConfig().dns_search_domains;
}

template <template <typename> class ChannelTpl>
DataPathStats ClientControlPlane<ChannelTpl>::GetStats() const
{
    return stats_;
}

template <template <typename> class ChannelTpl>
std::chrono::seconds ClientControlPlane<ChannelTpl>::GetUptime() const
{
    if (state_ != VpnClientState::Connected)
        return std::chrono::seconds(0);
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - connected_at_);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::SetStateCallback(StateCallback cb)
{
    state_callback_ = std::move(cb);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::TouchLastRx()
{
    last_rx_ns_.store(
        std::chrono::steady_clock::now().time_since_epoch().count(),
        std::memory_order_relaxed);
}

template <template <typename> class ChannelTpl>
ClientControlPlane<ChannelTpl>::ClientControlPlane(ClientControlConfig cfg)
    : io_context_(&cfg.io_context),
      config_(&cfg.config),
      logger_(&cfg.logger),
      running_(&cfg.running),
      data_adapter_(*this),
      channel_(*io_context_, *logger_, *config_, *running_, data_adapter_)
{
    stats_timer_.emplace(*io_context_);
    keepalive_timer_.emplace(*io_context_);
    handshake_timer_.emplace(*io_context_);

    control_channel_.emplace(*logger_);
    crypto_context_.emplace(*logger_);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::Connect()
{
    logger_->info("Connecting to {}:{}", config_->client->server_host, config_->client->server_port);
    SetState(VpnClientState::Connecting);

    auto resolved = openvpn::ResolveDataCipherPolicy(config_->client->data_ciphers,
                                                     config_->client->allow_deprecated_data_ciphers);
    effective_data_ciphers_ = std::move(resolved.effective_ciphers);
    for (const auto &cipher : resolved.deprecated_ciphers)
        logger_->warn("Deprecated data-cipher '{}' enabled by explicit operator policy", cipher);

    InitializeTransport();

    local_session_id_ = openvpn::SessionId::Generate().value;

    if (!LoadTlsCryptKey())
        return;
    if (!InitializeControlChannel())
        return;

    *running_ = true;
    TouchLastRx();

    asio::co_spawn(*io_context_, ConnectionLoop(), asio::detached);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::Disconnect()
{
    if (state_ == VpnClientState::Disconnected)
        return;

    logger_->info("Disconnecting...");
    *running_ = false;

    ch().StopDataPath();

    if (handshake_timer_)
        handshake_timer_->cancel();

    // Close the socket to unblock pending receives
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
        {
            asio::error_code ec;
            [[maybe_unused]] auto _ = udp->RawSocket().close(ec);
        }
        else if (auto *tcp = std::get_if<transport::TcpTransport>(&*transport_))
        {
            tcp->Close();
        }
    }
    transport_.reset();

    ch().OnTeardown();

    if (control_channel_)
        control_channel_->Reset();
    tls_crypt_.reset();
    tls_crypt_replay_.Reset();

    client_random_.clear();
    server_random_.clear();
    key_id_ = 0;
    remote_session_id_ = 0;
    server_peer_id_ = 0;
    config_exchange_.Reset();

    if (stats_timer_)
        stats_timer_->cancel();
    if (keepalive_timer_)
        keepalive_timer_->cancel();

    rekey_timer_armed_ = false;
    ++rekey_generation_;
    effective_data_ciphers_.clear();
    negotiated_cipher_.clear();

    SetState(VpnClientState::Disconnected);
    logger_->info("Disconnected");
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::OnControlPacketFromDataPath(std::vector<std::uint8_t> data)
{
    asio::co_spawn(*io_context_,
                   ProcessServerPacket(std::move(data)),
                   asio::detached);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ConnectionLoop()
{
    using namespace asio::experimental::awaitable_operators;
    static constexpr auto kHandshakeRetransmitInterval = std::chrono::seconds(2);
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(30);

    try
    {
        co_await SendHardReset();
        auto handshake_start = std::chrono::steady_clock::now();

        while (*running_)
        {
            if (state_ == VpnClientState::Connected)
                co_return;

            if (state_ == VpnClientState::TlsHandshake)
            {
                if (std::chrono::steady_clock::now() - handshake_start > kHandshakeTimeout)
                    throw std::runtime_error("TLS handshake timed out (30s)");

                auto timer_wait = [&]() -> asio::awaitable<void>
                {
                    handshake_timer_->expires_after(kHandshakeRetransmitInterval);
                    co_await handshake_timer_->async_wait(asio::use_awaitable);
                };

                auto result = co_await (transport_->Receive() || timer_wait());

                if (result.index() == 0)
                {
                    auto &data = std::get<0>(result);
                    if (!data.empty())
                        co_await ProcessServerPacket(std::move(data));
                }
                else
                {
                    auto retransmits = control_channel_->ProcessRetransmissions();
                    for (auto &pkt : retransmits)
                    {
                        co_await SendWrappedPacket(std::move(pkt));
                        logger_->debug("Retransmitted control packet");
                    }
                }
            }
            else
            {
                auto data = co_await transport_->Receive();
                if (data.empty())
                    continue;
                co_await ProcessServerPacket(std::move(data));
            }
        }
    }
    catch (const std::exception &e)
    {
        logger_->error("Connection error: {}", e.what());
        if (*running_ && state_ != VpnClientState::Reconnecting)
        {
            SetState(VpnClientState::Reconnecting);
            asio::co_spawn(*io_context_, ReconnectLoop(), asio::detached);
        }
        else
        {
            SetState(VpnClientState::Error);
        }
    }
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ReconnectLoop()
{
    const int max_attempts = config_->client->max_reconnect_attempts;

    while (max_attempts == 0 || reconnect_attempts_ < max_attempts)
    {
        ++reconnect_attempts_;
        logger_->info("Reconnecting (attempt {}/{})",
                      reconnect_attempts_,
                      max_attempts == 0 ? std::string("unlimited") : std::to_string(max_attempts));

        Disconnect();

        asio::steady_timer timer(*io_context_);
        timer.expires_after(std::chrono::seconds(config_->client->reconnect_delay_seconds));
        co_await timer.async_wait(asio::use_awaitable);

        try
        {
            Connect();
            co_return;
        }
        catch (const std::exception &e)
        {
            logger_->error("Reconnect attempt {} failed: {}", reconnect_attempts_, e.what());
            SetState(VpnClientState::Reconnecting);
        }
    }

    logger_->error("Max reconnect attempts ({}) reached", max_attempts);
    SetState(VpnClientState::Error);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::SendHardReset()
{
    const bool v2_mode = !tls_crypt_v2_wkc_.empty();
    const int reset_version = v2_mode ? 3 : 2;

    logger_->debug("Sending HARD_RESET_CLIENT_V{}", reset_version);
    std::uint32_t pkt_id = control_channel_->GetNextPacketId();

    auto packet = openvpn::OpenVpnPacket::HardReset(
        true, reset_version, key_id_, local_session_id_, pkt_id);

    auto serialized = packet.Serialize();

    if (v2_mode)
    {
        // Advertise early negotiation for tls-crypt-v2 (psid cookie / WKc resend).
        if (!co_await SendV2WkcControl(std::move(serialized), openvpn::EARLY_NEG_START, "hard reset"))
            co_return;
    }
    else
    {
        if (tls_crypt_)
        {
            auto wrapped = tls_crypt_->Wrap(serialized, false);
            if (!wrapped)
            {
                logger_->error("Failed to wrap hard reset");
                SetState(VpnClientState::Error);
                co_return;
            }
            serialized = std::move(*wrapped);
        }
        co_await SendRawPacket(serialized);
    }

    SetState(VpnClientState::TlsHandshake);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ProcessServerPacket(std::vector<std::uint8_t> data)
{
    if (data.empty())
        co_return;

    TouchLastRx();

    auto packet = UnwrapAndParse(data, tls_crypt_, openvpn::PeerRole::Client, *logger_, tls_crypt_replay_);
    if (!packet)
        co_return;

    if (openvpn::IsDataPacket(packet->opcode_))
    {
        if (state_ == VpnClientState::Connected)
        {
            if (unexpected_data_on_control_limiter_.Due())
            {
                const auto suppressed = unexpected_data_on_control_limiter_.SuppressedCount() + 1;
                logger_->warn("Dropping data packet on control plane ({}x)", suppressed);
            }
            co_return;
        }
        co_await HandleDataPacket(*packet);
    }
    else
        co_await HandleControlPacket(*packet);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::HandleControlPacket(const openvpn::OpenVpnPacket &packet)
{
    logger_->debug("Control packet: opcode={}", static_cast<int>(packet.opcode_));

    if (packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V2
        || packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V1)
    {
        remote_session_id_ = packet.session_id_.value_or(0);
        control_channel_->HandleHardReset(packet);

        const auto flags = openvpn::ParseEarlyNegFlagsTlv(packet.payload_);
        const bool resend_wkc = flags
                                && ((*flags & openvpn::EARLY_NEG_FLAG_RESEND_WKC) != 0)
                                && !tls_crypt_v2_wkc_.empty();

        SetState(VpnClientState::TlsHandshake);

        if (resend_wkc)
        {
            // OpenVPN cookie path: P_CONTROL_WKC_V1 with ACK + empty payload + WKc.
            auto serialized = control_channel_->GenerateWkcResendPacket();
            if (serialized.empty())
            {
                logger_->error("Failed to build P_CONTROL_WKC_V1");
                SetState(VpnClientState::Error);
                co_return;
            }
            if (!co_await SendV2WkcControl(std::move(serialized), std::nullopt, "P_CONTROL_WKC_V1"))
                co_return;
            logger_->info("Sent P_CONTROL_WKC_V1 (psid cookie WKc resend)");
        }
        else
        {
            auto ack = control_channel_->GenerateExplicitAck();
            if (!ack.empty())
                co_await SendWrappedPacket(std::move(ack));
        }

        auto client_hello = control_channel_->InitiateTlsHandshake();
        if (client_hello && !client_hello->empty())
            co_await SendWrappedPacket(std::move(*client_hello));

        co_await FlushControlQueue(*control_channel_,
                                   tls_crypt_,
                                   openvpn::PeerRole::Client,
                                   *transport_,
                                   *logger_);
        co_return;
    }

    if (control_channel_->PeerSidMismatch(packet))
    {
        logger_->warn(
            "Dropping control opcode {} — wire sid {:016x} != peer sid {:016x}",
            static_cast<int>(packet.opcode_),
            packet.session_id_.value_or(0),
            control_channel_->GetPeerSessionId()->value);
        co_return;
    }

    struct SessionActions
    {
        ClientControlPlane<ChannelTpl> &self;

        asio::awaitable<void> OnSoftReset(const openvpn::OpenVpnPacket &pkt)
        {
            co_await self.HandleSoftResetFromServer(pkt);
        }
        asio::awaitable<void> OnPlaintext(std::vector<std::uint8_t> plaintext)
        {
            co_await self.ProcessReceivedPlaintext(std::move(plaintext));
        }
        asio::awaitable<void> OnHandshakeComplete()
        {
            if (self.client_random_.empty())
                co_await self.ProcessTlsHandshake();
        }
    };
    SessionActions actions{*this};

    co_await DispatchSessionControlPacket(*control_channel_,
                                          tls_crypt_,
                                          openvpn::PeerRole::Client,
                                          *transport_,
                                          packet,
                                          *logger_,
                                          actions);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void>
ClientControlPlane<ChannelTpl>::HandleSoftResetFromServer(const openvpn::OpenVpnPacket &packet)
{
    last_server_rekey_at_ = std::chrono::steady_clock::now();

    const openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

    // Crossed soft-reset: we already called RequestSoftReset /
    // InitiateTlsHandshake. ControlChannel::RespondToSoftReset will ACK without
    // advancing key_id again — do not clear randoms or re-fire ClientHello, or
    // we corrupt the in-flight TLS state.
    if (control_channel_->GetState() == openvpn::ControlChannel::State::TlsHandshake)
    {
        logger_->info("Crossed soft reset: already renegotiating, ACKing server reset");
        auto response = control_channel_->RespondToSoftReset(packet, cert_config);
        if (!response.empty())
            co_await SendWrappedPacket(std::move(response));
        co_return;
    }

    logger_->info("Received soft reset from server — starting key renegotiation");

    auto response = control_channel_->RespondToSoftReset(packet, cert_config);
    if (!response.empty())
        co_await SendWrappedPacket(std::move(response));

    // Reset key exchange state so on_handshake_complete fires for the new session.
    client_random_.clear();
    server_random_.clear();

    // Kick off the new TLS ClientHello.
    auto client_hello = control_channel_->InitiateTlsHandshake();
    if (client_hello && !client_hello->empty())
        co_await SendWrappedPacket(std::move(*client_hello));
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ClientRekeyLoop(std::uint32_t reneg_seconds,
                                                                      std::uint64_t generation)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(reneg_seconds);
    const auto poll = co_await PollUntilRekey(
        *io_context_,
        deadline,
        [this, generation]
    {
        return *running_ && state_ == VpnClientState::Connected && rekey_generation_ == generation;
    },
        [this]
    { return ch().GetLimitsCryptoContext().TakeRekeyRequest(); });

    if (poll == RekeyPollResult::Cancelled)
    {
        rekey_timer_armed_ = false;
        co_return;
    }

    // Suppress client-initiated rekey if the server has driven one within the rekey window.
    auto elapsed = std::chrono::steady_clock::now() - last_server_rekey_at_;
    if (elapsed < std::chrono::seconds(reneg_seconds))
    {
        logger_->info("Client rekey suppressed: server rekeyed {}s ago, re-arming in {}s",
                      std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(),
                      reneg_seconds);
        asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
        co_return;
    }

    // Server already drove a soft reset (or we are mid-handshake) — yield.
    if (control_channel_->GetState() == openvpn::ControlChannel::State::TlsHandshake)
    {
        logger_->info("Client rekey suppressed: already renegotiating");
        asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
        co_return;
    }

    try
    {
        const openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

        auto soft_reset = control_channel_->RequestSoftReset(openvpn::PeerRole::Client, cert_config);
        if (soft_reset.empty())
        {
            logger_->warn("Client rekey: RequestSoftReset not ready, deferring");
            asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
            co_return;
        }

        client_random_.clear();
        server_random_.clear();

        co_await SendWrappedPacket(std::move(soft_reset));
        logger_->debug("Client rekey: sent P_CONTROL_SOFT_RESET_V1");

        // The VPN client is always TLS client — send the ClientHello to start
        // the renegotiation handshake.
        auto client_hello = control_channel_->InitiateTlsHandshake();
        if (client_hello && !client_hello->empty())
            co_await SendWrappedPacket(std::move(*client_hello));
    }
    catch (const std::exception &e)
    {
        logger_->warn("Client rekey: exception: {}", e.what());
    }

    // Rearm for next cycle regardless of outcome.
    asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::HandleDataPacket(const openvpn::OpenVpnPacket &packet)
{
    auto plaintext = crypto_context_->DecryptPacket(packet);
    if (plaintext.empty())
    {
        logger_->warn("Failed to decrypt data packet");
        co_return;
    }

    switch (openvpn::ClassifyDecryptedPayload(plaintext))
    {
    case openvpn::DecryptedPayloadDisposition::Drop:
        co_return;
    case openvpn::DecryptedPayloadDisposition::Keepalive:
        co_return;
    case openvpn::DecryptedPayloadDisposition::Forward:
        break;
    }

    stats_.packetsDecrypted++;

    co_await ch().DeliverDecryptedPacket(std::move(plaintext));
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ProcessTlsHandshake()
{
    if (control_channel_->GetState() == openvpn::ControlChannel::State::KeyMaterialReady)
    {
        client_random_.resize(openvpn::CLIENT_KEY_SOURCE_SIZE);
        if (RAND_bytes(client_random_.data(), static_cast<int>(client_random_.size())) != 1)
            throw std::runtime_error("RAND_bytes failed");

        std::string options = BuildKeyMethod2Options(
            openvpn::PeerRole::Client,
            config_->client->proto,
            config_->client->cipher,
            kDefaultTunMtu,
            config_->client->ipv6_only);

        auto peer_info = openvpn::BuildClientPeerInfo("clv-vpncore/1.0.0", effective_data_ciphers_);
        auto key_method_msg = openvpn::BuildKeyMethod2Message(client_random_, options, "", "", peer_info);

        co_await SendTlsControlData(
            *control_channel_, tls_crypt_, std::span<const uint8_t>(key_method_msg), openvpn::PeerRole::Client, *transport_, *logger_, "key-method 2");
    }
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext)
{
    if (plaintext.empty())
        co_return;

    auto view_len = plaintext.size();
    if (plaintext.back() == 0)
        --view_len;

    std::string_view data_view(reinterpret_cast<const char *>(plaintext.data()), view_len);
    if (data_view.empty())
        co_return;

    if (data_view.starts_with("PUSH_REPLY"))
    {
        co_await HandlePushReply(std::string(data_view.substr(11)));
        co_return;
    }

    if (plaintext.size() > 1 && plaintext[0] == 0x00)
    {
        auto parsed = openvpn::ParseKeyMethod2Message(plaintext, true);
        if (!parsed)
        {
            logger_->error("Failed to parse server key-method 2");
            SetState(VpnClientState::Error);
            co_return;
        }

        auto &[server_random, server_options, username, password, peer_info_ignored] = *parsed;
        server_random_ = std::move(server_random);

        DeriveAndInstallKeys();

        if (state_ == VpnClientState::Connected)
        {
            // Renegotiation — keys are installed; tunnel stays up as-is.
            logger_->info("Rekey complete — new data channel keys installed");
            co_return;
        }

        co_await SendPushRequest();
        SetState(VpnClientState::Authenticating);
        co_return;
    }

    logger_->warn("Unknown plaintext: {} bytes", plaintext.size());
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::SendPushRequest()
{
    std::string push_request = "PUSH_REQUEST";
    std::vector<std::uint8_t> message(push_request.begin(), push_request.end());
    message.push_back(0);

    co_await SendTlsControlData(
        *control_channel_, tls_crypt_, std::span<const std::uint8_t>(message), openvpn::PeerRole::Client, *transport_, *logger_, "PUSH_REQUEST");
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::HandlePushReply(const std::string &reply)
{
    struct Actions
    {
        ClientControlPlane &self;
        void DeriveAndInstallKeys()
        {
            self.DeriveAndInstallKeys();
        }
        void ApplyNetworkConfig()
        {
            self.ApplyNegotiatedNetworkConfig();
        }
        void MarkConnected()
        {
            self.SetState(VpnClientState::Connected);
        }
        void ScheduleRekey(std::uint32_t r, std::uint64_t g)
        {
            asio::co_spawn(*self.io_context_, self.ClientRekeyLoop(r, g), asio::detached);
        }
    };

    ClientPushReplyData data{
        .config_exchange = config_exchange_,
        .allowed_ciphers = effective_data_ciphers_,
        .current_cipher = config_->client->cipher,
        .client_renegotiate_seconds = static_cast<std::uint32_t>(config_->client->renegotiate_seconds),
        .negotiated_cipher = negotiated_cipher_,
        .server_peer_id = server_peer_id_,
        .is_connected = (state_ == VpnClientState::Connected),
        .rekey_timer_armed = rekey_timer_armed_,
        .rekey_generation = rekey_generation_,
        .logger = *logger_,
    };

    Actions actions{*this};
    co_await HandleClientPushReply(reply, data, actions);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::ApplyNegotiatedNetworkConfig()
{
    const auto &negotiated = config_exchange_.GetNegotiatedConfig();
    if (negotiated.ifconfig.first.empty())
        throw std::runtime_error("No IP assigned by server");

    auto &channel = this->ch();
    channel.ConfigureNetworkInterface(negotiated, *config_, *io_context_);
    channel.InstallNegotiatedRoutes(negotiated);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::DeriveAndInstallKeys()
{
    const std::string &cipher = negotiated_cipher_.empty() ? config_->client->cipher : negotiated_cipher_;
    auto result = DeriveDataChannelKeys(*control_channel_,
                                        client_random_,
                                        server_random_,
                                        cipher,
                                        openvpn::PeerRole::Client,
                                        *logger_);
    if (!result)
        throw std::runtime_error("DeriveDataChannelKeys failed");

    std::uint8_t current_key_id = control_channel_->GetKeyId();

    ch().InstallDataPathKeys(result->key_material,
                             result->cipher_algo,
                             result->hmac_algo,
                             current_key_id,
                             *crypto_context_);
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::SendWrappedPacket(std::vector<std::uint8_t> data)
{
    co_await WrapAndSend(tls_crypt_, std::move(data), openvpn::PeerRole::Client, *transport_, *logger_);
}

template <template <typename> class ChannelTpl>
asio::awaitable<bool> ClientControlPlane<ChannelTpl>::SendV2WkcControl(
    std::vector<std::uint8_t> serialized,
    std::optional<std::uint32_t> counter_override,
    std::string_view description)
{
    if (tls_crypt_)
    {
        auto wrapped = tls_crypt_->Wrap(serialized, false, counter_override);
        if (!wrapped)
        {
            logger_->error("Failed to wrap {}", description);
            SetState(VpnClientState::Error);
            co_return false;
        }
        serialized = std::move(*wrapped);
    }
    serialized.insert(serialized.end(), tls_crypt_v2_wkc_.begin(), tls_crypt_v2_wkc_.end());
    co_await SendRawPacket(serialized);
    co_return true;
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::SendRawPacket(std::span<const std::uint8_t> data)
{
    co_await transport_->Send(data);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::SetState(VpnClientState new_state)
{
    if (state_ == new_state)
        return;

    auto old_state = state_;
    logger_->info("State: {} -> {}", VpnClientStateToString(old_state), VpnClientStateToString(new_state));
    state_ = new_state;

    if (state_callback_)
        state_callback_(old_state, new_state);

    if (new_state == VpnClientState::Connected)
    {
        reconnect_attempts_ = 0;
        connected_at_ = std::chrono::steady_clock::now();

        if (config_->performance.stats_interval_seconds > 0)
            asio::co_spawn(*io_context_, StatsLoop(), asio::detached);

        StartDataPath();
    }
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::StartDataPath()
{
    auto &channel = this->ch();

    try
    {
        channel.AttachTransport(*transport_, transport_->GetPeer(), server_peer_id_);
    }
    catch (const std::exception &e)
    {
        logger_->error("AttachTransport: {}", e.what());
        SetState(VpnClientState::Error);
        return;
    }

    asio::co_spawn(*io_context_, channel.StartDataPath(), asio::detached);

    channel.LaunchKeepalive(*io_context_,
                            [this]()
    { return KeepaliveLoop(); },
                            config_->client->keepalive_interval);

    logger_->info("Data path started");
}

// TODO: OK but not elegant.
template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::KeepaliveLoop()
{
    // Thin session wrapper so the generic KeepaliveLoop can drive the client
    // without knowing about the client/server distinction.
    using tp = std::chrono::steady_clock::time_point;
    struct SelfSession
    {
        ClientControlPlane<ChannelTpl> &ctrl;
        bool HasValidKeys() const noexcept
        {
            return true;
        }
        tp GetLastActivity() const
        {
            return ctrl.LastRxTime();
        }
        tp GetLastOutbound() const
        {
            return ctrl.LastTxTime();
        }
        void UpdateLastOutbound() noexcept
        {
        } // TX path already updates last_tx_ns_
    };

    return ::clv::vpn::KeepaliveLoop(
        "Client",
        *running_,
        *keepalive_timer_,
        std::chrono::seconds(config_->client->keepalive_interval),
        std::chrono::seconds(config_->client->keepalive_timeout),
        *logger_,
        [this]()
    { return std::array<SelfSession, 1>{SelfSession{*this}}; },
        [this](SelfSession &)
    { return ch().SendKeepalivePing(); },
        [this](SelfSession &)
    {
        *running_ = false;
        SetState(VpnClientState::Reconnecting);
        asio::co_spawn(*io_context_, ReconnectLoop(), asio::detached);
    });
}

template <template <typename> class ChannelTpl>
asio::awaitable<void> ClientControlPlane<ChannelTpl>::StatsLoop()
{
    co_await RunStatsLoop(
        *stats_timer_,
        std::chrono::seconds(config_->performance.stats_interval_seconds),
        *logger_,
        [this]
    { return *running_ && state_ == VpnClientState::Connected; },
        [this]
    { return ch().SnapshotStats(); },
        [this](const DataPathStats &delta, double elapsedSec)
    { LogStats(delta, elapsedSec); });
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::LogStats(const DataPathStats &delta, double elapsedSec)
{
    int actualRcvBuf = 0, actualSndBuf = 0;
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
            std::tie(actualRcvBuf, actualSndBuf) = udp->GetSocketBufferSizes();
    }

    decltype(delta.batchHist) batchHist;
    if constexpr (requires { ch().GetRxBatchWindow(); })
    {
        try
        {
            batchHist = ch().GetRxBatchWindow().SnapshotAndReset();
        }
        catch (...)
        {
        }
    }

    auto rxH = FormatBatchHist(batchHist, delta.batchSaturations);
    auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);

    std::string txBstStr = "---";
    if constexpr (requires { ch().GetTxBurstAvgWindow(); })
    {
        try
        {
            auto [bTotal, bCount] = ch().GetTxBurstAvgWindow().SnapshotAndReset();
            txBstStr = FormatAvgBurst(bTotal, bCount);
        }
        catch (...)
        {
        }
    }

    logger_->info("[stats] {:.1f}s: "
                  "rx={} ({:.0f}M) tx={} ({:.0f}M) "
                  "rx{} bst={} "
                  "buf={}/{}ms "
                  "dec={}/{} tun=r{}/w{} serr={} spf={}",
                  elapsedSec,
                  delta.packetsReceived,
                  rates.rxMbps,
                  delta.packetsSent,
                  rates.txMbps,
                  rxH,
                  txBstStr,
                  FormatBufMs(rates.rxBufMs),
                  FormatBufMs(rates.txBufMs),
                  delta.packetsDecrypted,
                  delta.decryptFailures,
                  delta.tunReads,
                  delta.tunWrites,
                  delta.sendErrors,
                  delta.txSmallPktFlush);
}

template <template <typename> class ChannelTpl>
void ClientControlPlane<ChannelTpl>::InitializeTransport()
{
    transport::ClientConnector connector = (config_->client->proto == "tcp")
                                               ? transport::ClientConnector(transport::TcpConnector(*io_context_))
                                               : transport::ClientConnector(transport::UdpConnector(*io_context_));

    auto transport = connector.Connect(config_->client->server_host,
                                       config_->client->server_port,
                                       false,
                                       config_->client->ipv6_only);
    auto peer = transport.GetPeer();
    logger_->info("Connected via {}: {}:{}",
                  transport.IsTcp() ? "TCP" : "UDP",
                  peer.addr.to_string(),
                  peer.port);
    transport_.emplace(std::move(transport));

    if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
    {
        udp->ApplySocketBuffers(config_->performance.socket_recv_buffer,
                                config_->performance.socket_send_buffer,
                                *logger_);
    }
    else if (auto *tcp = std::get_if<transport::TcpTransport>(&*transport_))
    {
        tcp->ApplySocketBuffers(config_->performance.socket_recv_buffer,
                                config_->performance.socket_send_buffer,
                                *logger_);
    }
}

template <template <typename> class ChannelTpl>
bool ClientControlPlane<ChannelTpl>::EmplaceTlsCrypt(std::optional<openvpn::TlsCrypt> tc)
{
    if (!tc)
    {
        SetState(VpnClientState::Error);
        return false;
    }
    tls_crypt_.emplace(std::move(*tc));
    return true;
}

template <template <typename> class ChannelTpl>
bool ClientControlPlane<ChannelTpl>::InstallV2ClientKey(
    std::optional<openvpn::TlsCryptV2::ClientKeyData> client_key)
{
    if (!client_key)
    {
        SetState(VpnClientState::Error);
        return false;
    }
    if (!EmplaceTlsCrypt(openvpn::TlsCrypt::FromKeyData(client_key->client_key, *logger_)))
        return false;
    tls_crypt_v2_wkc_ = std::move(client_key->wkc_blob);
    return true;
}

template <template <typename> class ChannelTpl>
bool ClientControlPlane<ChannelTpl>::LoadTlsCryptKey()
{
    // TLS-Crypt-V2 (per-client key) takes priority
    if (!config_->client->tls_crypt_v2_key_pem.empty())
        return InstallV2ClientKey(
            openvpn::TlsCryptV2::LoadClientKeyString(config_->client->tls_crypt_v2_key_pem, *logger_));

    if (!config_->client->tls_crypt_v2_key.empty())
        return InstallV2ClientKey(
            openvpn::TlsCryptV2::LoadClientKeyFile(config_->client->tls_crypt_v2_key.string(), *logger_));

    // TLS-Crypt V1
    if (!config_->client->tls_crypt_key_pem.empty())
        return EmplaceTlsCrypt(
            openvpn::TlsCrypt::FromKeyString(config_->client->tls_crypt_key_pem, *logger_));

    if (!config_->client->tls_crypt_key.empty())
        return EmplaceTlsCrypt(
            openvpn::TlsCrypt::FromKeyFile(config_->client->tls_crypt_key.string(), *logger_));

    return true;
}

template <template <typename> class ChannelTpl>
openvpn::TlsCertConfig ClientControlPlane<ChannelTpl>::MakeTlsCertConfig() const
{
    return openvpn::TlsCertConfig{
        .ca_cert = config_->client->ca_cert.string(),
        .local_cert = config_->client->cert.string(),
        .local_key = config_->client->key.string(),
        .ca_cert_pem = config_->client->ca_cert_pem,
        .local_cert_pem = config_->client->cert_pem,
        .local_key_pem = config_->client->key_pem};
}

template <template <typename> class ChannelTpl>
bool ClientControlPlane<ChannelTpl>::InitializeControlChannel()
{
    const openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

    openvpn::SessionId session_id{local_session_id_};
    if (!control_channel_->Initialize(openvpn::PeerRole::Client, session_id, cert_config))
    {
        SetState(VpnClientState::Error);
        return false;
    }
    return true;
}

template <template <typename> class ChannelTpl>
std::chrono::steady_clock::time_point ClientControlPlane<ChannelTpl>::LastRxTime() const
{
    return std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(last_rx_ns_.load(std::memory_order_relaxed)));
}


} // namespace clv::vpn

#include "client_dco_channel.h"
#include "client_tcp_channel.h"
#include "client_udp_channel.h"

namespace clv::vpn {

template class ClientControlPlane<ClientUdpChannel>;
template class ClientControlPlane<ClientDcoChannel>;
template class ClientControlPlane<ClientTcpChannel>;

} // namespace clv::vpn
