// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "control_plane_helpers.h"
#include "key_derivation.h"
#include "openvpn/control_channel.h"
#include "openvpn/packet.h"
#include "openvpn/tls_crypt.h"
#include "transport/transport.h"
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace clv::vpn {

asio::awaitable<void> WrapAndSend(std::optional<openvpn::TlsCrypt> &tls_crypt,
                                  std::vector<std::uint8_t> data,
                                  bool is_server,
                                  transport::TransportHandle &transport,
                                  spdlog::logger &logger)
{
    if (tls_crypt)
    {
        auto wrapped = tls_crypt->Wrap(data, is_server);
        if (!wrapped)
        {
            logger.error("TLS-Crypt wrap failed ({} byte payload)", data.size());
            co_return;
        }
        data = std::move(*wrapped);
    }

    try
    {
        co_await transport.Send(data);
    }
    catch (const std::exception &e)
    {
        logger.error("Error sending wrapped packet: {}", e.what());
    }
}

asio::awaitable<bool> SendTlsControlData(openvpn::ControlChannel &control_channel,
                                         std::optional<openvpn::TlsCrypt> &tls_crypt,
                                         std::span<const std::uint8_t> data,
                                         bool is_server,
                                         transport::TransportHandle &transport,
                                         spdlog::logger &logger,
                                         std::string_view description)
{
    auto fragments = control_channel.PrepareTlsEncryptedData(data);

    if (fragments.empty())
    {
        logger.error("Failed to prepare {} for TLS send", description);
        co_return false;
    }

    for (auto &fragment : fragments)
    {
        co_await WrapAndSend(tls_crypt,
                             std::vector<std::uint8_t>(fragment.begin(), fragment.end()),
                             is_server,
                             transport,
                             logger);
        logger.debug("Sent {} ({} bytes before wrap)", description, fragment.size());
    }

    co_return true;
}

asio::awaitable<void> FlushControlQueue(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        bool is_server,
                                        transport::TransportHandle &transport,
                                        spdlog::logger &logger)
{
    // 1. Flush queued fragments (e.g. remaining TLS handshake fragments)
    auto queued = control_channel.GetPacketsToSend();
    for (auto &fragment : queued)
    {
        co_await WrapAndSend(tls_crypt, std::move(fragment), is_server, transport, logger);
    }
    if (!queued.empty())
        logger.debug("Flushed {} queued fragment(s)", queued.size());

    // 2. Process retransmissions
    auto retransmits = control_channel.ProcessRetransmissions();
    for (auto &pkt : retransmits)
    {
        co_await WrapAndSend(tls_crypt, std::move(pkt), is_server, transport, logger);
        logger.debug("Retransmitted control packet");
    }
}

asio::awaitable<void> ProcessTlsDataAndRespond(openvpn::ControlChannel &control_channel,
                                               std::optional<openvpn::TlsCrypt> &tls_crypt,
                                               bool is_server,
                                               transport::TransportHandle &transport,
                                               const openvpn::OpenVpnPacket &packet,
                                               spdlog::logger &logger,
                                               bool suppress_ack)
{
    auto responses = control_channel.ProcessTlsData(packet);

    if (responses && !responses->empty())
    {
        for (auto &fragment : *responses)
        {
            if (!fragment.empty())
            {
                co_await WrapAndSend(tls_crypt, std::move(fragment), is_server, transport, logger);
            }
        }
        logger.debug("Sent {} TLS response fragment(s)", responses->size());
    }
    else if (!suppress_ack)
    {
        auto ack = control_channel.GenerateExplicitAck();
        if (!ack.empty())
        {
            co_await WrapAndSend(tls_crypt, std::move(ack), is_server, transport, logger);
            logger.debug("Sent ACK");
        }
    }
}

asio::awaitable<void> HandleAckAndDrain(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        bool is_server,
                                        transport::TransportHandle &transport,
                                        const openvpn::OpenVpnPacket &packet,
                                        spdlog::logger &logger)
{
    control_channel.HandleAck(packet);

    auto queued = control_channel.GetPacketsToSend();
    if (!queued.empty())
    {
        for (auto &fragment : queued)
        {
            co_await WrapAndSend(tls_crypt, std::move(fragment), is_server, transport, logger);
        }
        logger.debug("Sent {} queued fragment(s) after ACK", queued.size());
    }
}

std::optional<openvpn::KeyDerivation::KeyMethod2Result>
DeriveDataChannelKeys(openvpn::ControlChannel &control_channel,
                      std::span<const std::uint8_t> client_random,
                      std::span<const std::uint8_t> server_random,
                      std::string_view cipher_name,
                      bool is_server,
                      spdlog::logger &logger)
{
    auto local_sid = control_channel.GetSessionId();
    auto peer_sid_opt = control_channel.GetPeerSessionId();

    if (!peer_sid_opt)
    {
        logger.error("Peer session ID not available for PRF");
        return std::nullopt;
    }

    // The PRF always takes (client_sid, server_sid).  Determine which is
    // local vs peer based on the caller's role.
    auto client_sid = is_server ? *peer_sid_opt : local_sid;
    auto server_sid = is_server ? local_sid : *peer_sid_opt;

    logger.debug("PRF inputs: client_random={} bytes, server_random={} bytes",
                 client_random.size(),
                 server_random.size());
    logger.debug("  client_sid: {:016x}, server_sid: {:016x}, cipher: {}",
                 client_sid.value,
                 server_sid.value,
                 cipher_name);

    try
    {
        return openvpn::KeyDerivation::DeriveKeyMethod2(
            client_random, server_random, client_sid, server_sid, cipher_name);
    }
    catch (const std::exception &e)
    {
        logger.error("Key derivation failed: {}", e.what());
        return std::nullopt;
    }
}

std::optional<openvpn::OpenVpnPacket> UnwrapAndParse(
    std::vector<std::uint8_t> &data,
    std::optional<openvpn::TlsCrypt> &tls_crypt,
    bool is_server,
    spdlog::logger &logger)
{
    if (data.empty())
    {
        logger.debug("UnwrapAndParse: empty packet");
        return std::nullopt;
    }

    openvpn::Opcode opcode = openvpn::GetOpcode(data[0]);

    // Control packets are TLS-Crypt wrapped; data packets use session-key
    // encryption and pass through unchanged.
    if (!openvpn::IsDataPacket(opcode) && tls_crypt)
    {
        auto unwrapped = tls_crypt->Unwrap(data, is_server);
        if (!unwrapped)
        {
            logger.warn("TLS-Crypt unwrap failed for control packet (opcode {})",
                        static_cast<int>(opcode));
            return std::nullopt;
        }
        data = std::move(*unwrapped);
    }

    auto packet = openvpn::OpenVpnPacket::Parse(data);
    if (!packet)
    {
        logger.error("Failed to parse OpenVPN packet ({} bytes)", data.size());
        return std::nullopt;
    }

    return packet;
}

asio::awaitable<void> DispatchSessionControlPacket(
    openvpn::ControlChannel &control_channel,
    std::optional<openvpn::TlsCrypt> &tls_crypt,
    bool is_server,
    transport::TransportHandle &transport,
    const openvpn::OpenVpnPacket &packet,
    spdlog::logger &logger,
    const SessionControlCallbacks &callbacks)
{
    // 1. Dispatch based on opcode
    switch (packet.opcode_)
    {
    case openvpn::Opcode::P_CONTROL_V1:
        co_await ProcessTlsDataAndRespond(control_channel,
                                          tls_crypt,
                                          is_server,
                                          transport,
                                          packet,
                                          logger);
        break;

    case openvpn::Opcode::P_ACK_V1:
        co_await HandleAckAndDrain(control_channel, tls_crypt, is_server, transport, packet, logger);
        break;

    case openvpn::Opcode::P_CONTROL_SOFT_RESET_V1:
        if (callbacks.on_soft_reset)
        {
            co_await callbacks.on_soft_reset(packet);
        }
        else
        {
            logger.warn("Received soft reset but no handler registered");
        }
        break;

    default:
        logger.warn("DispatchSessionControlPacket: unhandled opcode {}",
                    static_cast<int>(packet.opcode_));
        break;
    }

    // 2. Flush queued fragments and retransmissions
    co_await FlushControlQueue(control_channel, tls_crypt, is_server, transport, logger);

    // 3. Post-TLS check: if handshake is complete, process any plaintext
    if (control_channel.GetState() == openvpn::ControlChannel::State::KeyMaterialReady)
    {
        if (control_channel.HasPlaintext())
        {
            auto plaintext = control_channel.ReadPlaintext();
            if (callbacks.on_plaintext)
            {
                co_await callbacks.on_plaintext(std::move(plaintext));
            }
        }
        else if (callbacks.on_handshake_complete)
        {
            co_await callbacks.on_handshake_complete();
        }
    }
}

} // namespace clv::vpn
