// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CHANNEL_CONCEPT_H
#define CLV_VPN_CHANNEL_CONCEPT_H

/**
 * @file channel_concept.h
 * @brief C++20 concepts for data-plane engines and control-plane DI contracts.
 *
 * Control planes own a Channel member constructed with a DataAdapter reference
 * (no SetAdapter / optional channel). Adapter/leaf concepts document template DI
 * surfaces (no vtables).
 */

#include "data_path_stats.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "transport/transport.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace clv::vpn {

class TunnelZone;

/** Shared data-plane engine surface (client and server). */
template <typename C>
concept Channel = requires(C &ch, const C &cch) {
    { ch.StartDataPath() };
    { ch.StopDataPath() };
    { cch.SnapshotStats() } -> std::same_as<DataPathStats>;
    { ch.SetBatchSize(std::size_t{}) };
    { cch.GetBatchSize() } -> std::convertible_to<std::size_t>;
};

/**
 * Server multi-peer / hub data engines (UDP userspace, TCP, DCO).
 * ConfigureDataPlane attaches the hub to @p zone via TunnelZoneAttachmentGuard.
 */
template <typename C>
concept ServerChannel = Channel<C> && requires(
    C &ch,
    const VpnConfig::ServerConfig &srv,
    asio::io_context &ioc,
    TunnelZone *zone,
    Connection *session,
    const openvpn::OpenVpnPacket &packet,
    std::span<std::uint8_t> datagram,
    const std::vector<std::uint8_t> &key_material,
    openvpn::CipherAlgorithm cipher,
    openvpn::HmacAlgorithm hmac,
    std::uint8_t key_id) {
    { ch.ConfigureDataPlane(srv, ioc, zone) } -> std::convertible_to<std::string>;
    { ch.InstallKeys(session, key_material, cipher, hmac, key_id) } -> std::same_as<bool>;
    { ch.ProcessIncomingDataPacket(session, packet) };
    { ch.DecryptAndStripInPlace(session, datagram) } -> std::same_as<std::span<std::uint8_t>>;
    { ch.SendKeepAlivePing(session) };
    { ch.RunKeepaliveMonitor() };
    { ch.StopKeepaliveMonitor() };
};

/**
 * Client uplink data engines (UDP userspace, TCP, DCO).
 */
template <typename C>
concept ClientChannel = Channel<C> && requires(
    C &ch,
    const C &cch,
    std::vector<std::uint8_t> plaintext,
    const std::vector<std::uint8_t> &key_material,
    openvpn::CipherAlgorithm cipher,
    openvpn::HmacAlgorithm hmac,
    std::uint8_t key_id,
    openvpn::CryptoContext &crypto,
    const openvpn::NegotiatedConfig &negotiated,
    const VpnConfig &config,
    asio::io_context &ioc) {
    { ch.DeliverDecryptedPacket(std::move(plaintext)) };
    { ch.SendKeepalivePing() };
    { cch.LastTxTime() } -> std::same_as<std::chrono::steady_clock::time_point>;
    { ch.InstallDataPathKeys(key_material, cipher, hmac, key_id, crypto) };
    { ch.GetLimitsCryptoContext() } -> std::same_as<openvpn::CryptoContext &>;
    { ch.OnTeardown() };
    { ch.ConfigureNetworkInterface(negotiated, config, ioc) };
};

/**
 * Control-plane surface injected into ServerDataAdapter (template DI).
 * Leaves provide these as ordinary methods (inherited defaults or name hiding).
 */
template <typename C>
concept ServerControlForAdapter = requires(
    C &c,
    std::vector<std::uint8_t> data,
    transport::PeerEndpoint ep,
    transport::TransportHandle th,
    openvpn::SessionId sid) {
    { c.io_context() } -> std::same_as<asio::io_context &>;
    { c.OnControlPacketFromDataPath(std::move(data), ep) };
    { c.OnControlPacketFromDataPath(std::move(data), ep, std::move(th)) };
    { c.HandleDeadPeer(sid) };
    { c.HandleTcpDisconnect(ep) };
};

/** Control-plane surface injected into ClientDataAdapter. */
template <typename C>
concept ClientControlForAdapter = requires(C &c, std::vector<std::uint8_t> data) {
    { c.io_context() } -> std::same_as<asio::io_context &>;
    { c.OnControlPacketFromDataPath(std::move(data)) };
    { c.TouchLastRx() };
};

/**
 * Server transport leaf: owns channel() and LogStats for ServerControlBase<Leaf>.
 * Assert after the leaf type is complete.
 */
template <typename L>
concept ServerTransportLeaf = requires(L &leaf, const L &cleaf, const DataPathStats &d, double t) {
    { leaf.channel() };
    { cleaf.channel() };
    { leaf.LogStats(d, t) };
} && ServerChannel<std::remove_cvref_t<decltype(std::declval<L &>().channel())>>;

} // namespace clv::vpn

#endif // CLV_VPN_CHANNEL_CONCEPT_H
