// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "userspace_data_channel.h"
#include "connection.h"
#include "control_channel.h"
#include "data_channel.h"
#include "data_path_stats.h"
#include "key_derivation.h"
#include "openvpn/protocol_constants.h"
#include "packet.h"
#include "session_manager.h"
#include <algorithm>
#include <atomic>
#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>
#include "../routing_table.h"
#include "transport/batch_constants.h"
#include "transport/transport.h"
#include <tun/tun_device.h>
#include <transport/udp_batch.h>

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <memory>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn {

UserspaceDataChannel::UserspaceDataChannel(asio::io_context &io_context,
                                           std::unique_ptr<tun::TunDevice> &tun_device,
                                           RoutingTableIpv4 &routing_table,
                                           RoutingTableIpv6 &routing_table_v6,
                                           SessionManager &session_manager,
                                           spdlog::logger &logger,
                                           DataPathStats &stats,
                                           StatsObserver &stats_observer,
                                           std::size_t batchSize,
                                           std::size_t processQuanta,
                                           int keepalive_interval,
                                           int keepalive_timeout,
                                           const std::atomic<bool> &running_flag)
    : io_context_(io_context),
      tun_device_(tun_device),
      routing_table_(routing_table),
      routing_table_v6_(routing_table_v6),
      session_manager_(session_manager),
      logger_(&logger),
      stats_(stats),
      stats_observer_(stats_observer),
      batchSize_(batchSize > 0
                     ? std::min(batchSize, transport::kMaxBatchSize)
                     : transport::kDefaultBatchSize),
      processQuanta_(processQuanta),
      keepalive_interval_(keepalive_interval > 0 ? keepalive_interval : 10),
      keepalive_timeout_(keepalive_timeout > 0 ? keepalive_timeout : 120),
      running_(running_flag),
      keepalive_timer_(io_context),
      outbound_arena_(batchSize > 0
                          ? std::min(batchSize, transport::kMaxBatchSize)
                          : transport::kDefaultBatchSize)
{
}

asio::awaitable<void>
UserspaceDataChannel::ProcessIncomingDataPacket(Connection *session,
                                                const openvpn::OpenVpnPacket &packet)
{
    // Decrypt data packet
    auto plaintext = session->GetDataChannel().DecryptPacket(packet);

    logger_->debug("DecryptPacket returned {} bytes", plaintext.size());

    if (!plaintext.empty())
    {
        stats_.packetsDecrypted++;

        // OpenVPN internal ping/keepalive packets are exactly 16 bytes with a magic prefix.
        // Check for these FIRST, before any compression byte stripping.
        if (openvpn::IsKeepalivePing(plaintext))
        {
            logger_->debug("Received OpenVPN keepalive ping from client");
            co_return;
        }

        // Check for OpenVPN compression framing byte.
        // If the first byte isn't an IP version nibble (4 or 6), it's a compression prefix.
        uint8_t first_byte = plaintext[0];
        uint8_t version_nibble = (first_byte >> openvpn::IP_VERSION_SHIFT) & openvpn::IP_VERSION_MASK;
        if (version_nibble != openvpn::IP_VERSION_4 && version_nibble != openvpn::IP_VERSION_6)
        {
            if (first_byte == openvpn::COMPRESS_NONE || first_byte == openvpn::COMPRESS_STUB_LZO)
            {
                logger_->debug("Stripping compression framing byte 0x{:02x}", first_byte);
                plaintext.erase(plaintext.begin());
                session->SetUsesCompressionFraming(true);
            }
            else
            {
                logger_->warn("Unknown non-IP byte 0x{:02x} in {} byte packet, dropping",
                              first_byte,
                              plaintext.size());
                co_return;
            }
        }

        // Check for keepalive after compress strip
        if (openvpn::IsKeepalivePing(plaintext))
        {
            logger_->debug("Received OpenVPN keepalive ping from peer (compressed)");
            co_return;
        }

        if (plaintext.size() < openvpn::IPV4_MIN_HEADER_SIZE)
        {
            logger_->debug("Ignoring packet too small to be valid IP (size={})", plaintext.size());
        }
        else
        {
            logger_->debug("Forwarding {} decrypted bytes to TUN device", plaintext.size());
            stats_.tunWrites++;
            tun::IpPacket ip_packet;
            ip_packet.data = std::move(plaintext);
            co_await SendToTun(ip_packet);
        }
    }
    else
    {
        stats_.decryptFailures++;
        logger_->warn("DecryptPacket returned empty (decryption failed)");
    }

    co_return;
}

// ---------------------------------------------------------------------------
// DecryptAndStripInPlace — synchronous decrypt + compress strip (no TUN write)
// ---------------------------------------------------------------------------

std::span<std::uint8_t>
UserspaceDataChannel::DecryptAndStripInPlace(Connection *session,
                                             std::span<std::uint8_t> datagram)
{
    auto plaintext = session->GetDataChannel().DecryptPacketInPlace(datagram);

    if (plaintext.empty())
    {
        stats_.decryptFailures++;
        return {};
    }

    stats_.packetsDecrypted++;

    // Check for raw keepalive magic (no compress byte)
    if (openvpn::IsKeepalivePing(plaintext))
    {
        logger_->debug("Received OpenVPN keepalive ping from peer");
        return {}; // Consumed — not forwarded to TUN
    }

    // Strip compression framing byte if present
    std::span<std::uint8_t> ip_data = plaintext;
    uint8_t first_byte = ip_data[0];
    uint8_t version_nibble = (first_byte >> openvpn::IP_VERSION_SHIFT) & openvpn::IP_VERSION_MASK;
    if (version_nibble != openvpn::IP_VERSION_4 && version_nibble != openvpn::IP_VERSION_6)
    {
        if (first_byte == openvpn::COMPRESS_NONE || first_byte == openvpn::COMPRESS_STUB_LZO)
        {
            ip_data = ip_data.subspan(1); // Advance past compress byte — no alloc
            session->SetUsesCompressionFraming(true);
        }
        else
        {
            logger_->warn("Unknown non-IP byte 0x{:02x} in {} byte packet, dropping",
                          first_byte,
                          ip_data.size());
            return {};
        }
    }

    // Check for keepalive after compress strip
    if (openvpn::IsKeepalivePing(ip_data))
    {
        logger_->debug("Received OpenVPN keepalive ping from peer (compressed)");
        return {}; // Consumed — not forwarded to TUN
    }

    if (ip_data.size() < openvpn::IPV4_MIN_HEADER_SIZE)
        return {};

    return ip_data;
}

// ---------------------------------------------------------------------------
// EncryptTunPacket — shared route + session + compress + encrypt logic
// ---------------------------------------------------------------------------

std::optional<UserspaceDataChannel::EncryptedResult>
UserspaceDataChannel::EncryptTunPacket(tun::IpPacket &packet)
{
    // Determine IP version and look up destination in routing table
    std::optional<uint64_t> session_id_opt;

    if (packet.data.size() >= 1)
    {
        uint8_t version = (packet.data[0] >> 4) & 0x0F;
        if (version == 4)
        {
            auto dest_ipv4 = ExtractDestIpv4(packet);
            if (dest_ipv4)
                session_id_opt = routing_table_.Lookup(*dest_ipv4);
        }
        else if (version == 6)
        {
            auto dest_ipv6 = ExtractDestIpv6(packet);
            if (dest_ipv6)
                session_id_opt = routing_table_v6_.Lookup(*dest_ipv6);
        }
        else
        {
            logger_->debug("EncryptTunPacket: Dropping unknown IP version {} ({} bytes)",
                           version,
                           packet.data.size());
            return std::nullopt;
        }
    }

    if (!session_id_opt)
    {
        stats_.routeLookupMisses++;
        return std::nullopt;
    }

    openvpn::SessionId session_id{*session_id_opt};
    auto *session = session_manager_.FindSession(session_id);
    if (!session)
        return std::nullopt;

    // Verify session is ready for data
    using State = openvpn::ControlChannel::State;
    auto state = session->GetControlChannel().GetState();
    bool session_ready = (state == State::Active || state == State::KeyMaterialReady);

    // Data keys may be installed even if control channel state tracking lags
    if (!session_ready && session->GetDataChannel().HasValidKeys())
    {
        logger_->debug("EncryptTunPacket: Control state {} but data keys installed, proceeding",
                       static_cast<int>(state));
        session_ready = true;
    }
    if (!session_ready)
        return std::nullopt;

    // Compression framing — prepend NO_COMPRESS marker if client expects it
    std::vector<std::uint8_t> encrypt_input;
    if (session->UsesCompressionFraming())
    {
        encrypt_input.reserve(1 + packet.data.size());
        encrypt_input.push_back(openvpn::COMPRESS_NONE);
        encrypt_input.insert(encrypt_input.end(), packet.data.begin(), packet.data.end());
    }
    else
    {
        encrypt_input = std::move(packet.data);
    }

    auto encrypted = session->GetDataChannel().EncryptPacket(encrypt_input, session_id);
    if (encrypted.empty())
    {
        logger_->warn("EncryptTunPacket: Encryption failed");
        return std::nullopt;
    }
    stats_.packetsEncrypted++;

    return EncryptedResult{
        .encrypted = std::move(encrypted),
        .session = session,
    };
}

// ---------------------------------------------------------------------------
// ProcessOutgoingTunPacket — per-packet coroutine path (TCP + UDP fallback)
// ---------------------------------------------------------------------------

asio::awaitable<void> UserspaceDataChannel::ProcessOutgoingTunPacket(tun::IpPacket packet)
{
    auto result = EncryptTunPacket(packet);
    if (!result)
        co_return;

    auto *session = result->session;

    logger_->debug("ProcessOutgoingTunPacket: {} encrypted bytes, session={:016x}, transport={}",
                   result->encrypted.size(),
                   session->GetSessionId().value,
                   session->GetTransport().IsTcp() ? "TCP" : "UDP");

    if (!session->HasTransport())
    {
        logger_->error("ProcessOutgoingTunPacket: Session has no transport handle");
        co_return;
    }

    try
    {
        co_await session->GetTransport().Send(result->encrypted);
        stats_.packetsSent++;
        stats_.bytesSent += result->encrypted.size();
    }
    catch (const std::exception &e)
    {
        stats_.sendErrors++;
        logger_->error("Error sending to client: {}", e.what());
    }

    co_return;
}

// ---------------------------------------------------------------------------
// PrepareOutgoingPacket — synchronous encrypt + route lookup (no send)
// ---------------------------------------------------------------------------

std::optional<UserspaceDataChannel::PreparedPacket>
UserspaceDataChannel::PrepareOutgoingPacket(tun::IpPacket &packet)
{
    auto result = EncryptTunPacket(packet);
    if (!result)
        return std::nullopt;

    auto *session = result->session;

    if (!session->HasTransport())
        return std::nullopt;

    // Only batch transports that support sendmmsg — TCP falls back to per-packet coroutine
    auto &transport = session->GetTransport();
    if (!transport.IsBatchingSupported())
        return std::nullopt;

    auto &udp = std::get<transport::UdpTransport>(transport);
    int fd = udp.RawSocket().native_handle();

    return PreparedPacket{
        .encrypted = std::move(result->encrypted),
        .dest = transport.GetPeer(),
        .socketFd = fd,
    };
}

asio::awaitable<void> UserspaceDataChannel::StartTunReceiver()
{
    logger_->info("Starting TUN packet receiver (batch_size={}, arena={}KB)",
                  batchSize_,
                  outbound_arena_.TotalSize() / 1024);

    // One-time setup for arena-based outbound path
    sendEntries_.reserve(batchSize_);
    arena_entries_.reserve(batchSize_);

    // Pre-allocate TUN read slot descriptors — each points into the arena at
    // offset kDataV2Overhead+1, leaving room for the wire header + compress byte.
    // IP data lands at arena[i]+25; compress byte goes at arena[i]+24 if needed.
    tun_slots_.resize(batchSize_);
    constexpr std::size_t kTunReadOffset = openvpn::kDataV2Overhead + 1;
    for (std::size_t i = 0; i < batchSize_; ++i)
    {
        tun_slots_[i].buf = outbound_arena_.Slot(i) + kTunReadOffset;
        tun_slots_[i].capacity = outbound_arena_.SlotSize() - kTunReadOffset;
        tun_slots_[i].len = 0;
    }

    // Keep old path's vectors for the non-batchable fallback (TCP transport etc.)
    prepared_.reserve(batchSize_);

    while (tun_running_)
    {
        try
        {
            // ---- Read TUN packets directly into arena slots ----
            // IP data lands at arena[i] + kDataV2Overhead + 1 (offset 25)
            for (auto &s : tun_slots_)
                s.len = 0;

            auto count = co_await tun_device_->ReadBatchInto(
                std::span<tun::TunDevice::SlotBuffer>(tun_slots_.data(), batchSize_));
            stats_.tunReads += count;
            stats_.RecordTunReadBatch(count, batchSize_);

            if (count > 0)
                logger_->debug("StartTunReceiver: read {} packets from TUN", count);
            stats_observer_.RecordTxBatchHistogram(count);

            // ---- Encrypt + send in quanta-sized chunks ----
            // quanta == 0 → process the full batch in one pass (no yields).
            // quanta  > 0 → process quanta packets at a time, flushing each
            // chunk via sendmmsg and yielding between chunks so the RX
            // coroutine (which must forward ACKs) can make progress.
            const std::size_t quanta = processQuanta_;
            const std::size_t effectiveQuanta = (quanta == 0) ? count : quanta;

            for (std::size_t chunk_start = 0; chunk_start < count; chunk_start += effectiveQuanta)
            {
                const std::size_t chunk_end = std::min(chunk_start + effectiveQuanta, count);
                sendEntries_.clear();
                arena_entries_.clear();
                int socketFd = -1;

                for (std::size_t i = chunk_start; i < chunk_end; ++i)
                {
                    const std::size_t ip_len = tun_slots_[i].len;
                    if (ip_len < openvpn::IPV4_MIN_HEADER_SIZE)
                        continue;

                    auto *ip_data = outbound_arena_.Slot(i) + kTunReadOffset;

                    // Route lookup — branch on IP version
                    std::optional<uint64_t> session_id_opt;
                    const uint8_t ip_version = ip_data[0] >> 4;
                    if (ip_version == 4)
                    {
                        // Extract destination IPv4 from IP header bytes 16-19
                        uint32_t dest_ipv4 = (static_cast<uint32_t>(ip_data[16]) << 24)
                                             | (static_cast<uint32_t>(ip_data[17]) << 16)
                                             | (static_cast<uint32_t>(ip_data[18]) << 8)
                                             | static_cast<uint32_t>(ip_data[19]);
                        session_id_opt = routing_table_.Lookup(dest_ipv4);
                    }
                    else if (ip_version == 6)
                    {
                        // IPv6 minimum header is 40 bytes; dest addr at bytes 24-39
                        if (ip_len < 40)
                            continue;
                        ipv6::Ipv6Address dest_v6;
                        std::memcpy(dest_v6.data(), ip_data + 24, 16);
                        session_id_opt = routing_table_v6_.Lookup(dest_v6);
                    }
                    else
                    {
                        logger_->debug("StartTunReceiver: Dropping unknown IP version {} ({} bytes)",
                                       ip_version,
                                       ip_len);
                        continue;
                    }

                    if (!session_id_opt)
                    {
                        stats_.routeLookupMisses++;
                        if (ip_version == 4)
                        {
                            logger_->debug("StartTunReceiver: rmiss IPv4 dst={}.{}.{}.{}",
                                           ip_data[16],
                                           ip_data[17],
                                           ip_data[18],
                                           ip_data[19]);
                        }
                        else
                        {
                            logger_->debug("StartTunReceiver: rmiss IPv6 ({} bytes)", ip_len);
                        }
                        continue;
                    }

                    openvpn::SessionId session_id{*session_id_opt};
                    auto *session = session_manager_.FindSession(session_id);
                    if (!session)
                        continue;

                    // Verify session is ready for data
                    using State = openvpn::ControlChannel::State;
                    auto state = session->GetControlChannel().GetState();
                    bool session_ready = (state == State::Active || state == State::KeyMaterialReady);
                    if (!session_ready && session->GetDataChannel().HasValidKeys())
                        session_ready = true;
                    if (!session_ready)
                        continue;

                    // Check if batchable (transport supports sendmmsg)
                    if (!session->HasTransport() || !session->GetTransport().IsBatchingSupported())
                    {
                        // Non-batching fallback (TCP).  Inline the co_await so
                        // the send is serialized within this coroutine — avoids
                        // a detached co_spawn that would capture `this` without
                        // any lifetime guarantee.
                        tun::IpPacket pkt;
                        pkt.data.assign(ip_data, ip_data + ip_len);
                        co_await ProcessOutgoingTunPacket(std::move(pkt));
                        continue;
                    }

                    // ---- Arena in-place encrypt ----
                    auto *slot = outbound_arena_.Slot(i);
                    std::size_t payload_len;
                    if (session->UsesCompressionFraming())
                    {
                        // Write compress-none marker at offset 24; IP data already at 25
                        slot[openvpn::kDataV2Overhead] = openvpn::COMPRESS_NONE;
                        payload_len = 1 + ip_len;
                    }
                    else
                    {
                        // Shift IP data from offset 25 to 24 (1-byte memmove, hot cache)
                        std::memmove(slot + openvpn::kDataV2Overhead,
                                     slot + openvpn::kDataV2Overhead + 1,
                                     ip_len);
                        payload_len = ip_len;
                    }

                    auto wire_len = session->GetDataChannel().EncryptPacketInPlace(
                        outbound_arena_.SlotSpan(i), payload_len, session_id);
                    if (wire_len == 0)
                        continue;

                    stats_.packetsEncrypted++;

                    auto &udp = std::get<transport::UdpTransport>(session->GetTransport());
                    if (socketFd < 0)
                        socketFd = udp.RawSocket().native_handle();

                    sendEntries_.push_back(transport::SendEntry{
                        .data = std::span<const std::uint8_t>(slot, wire_len),
                        .dest = session->GetTransport().GetPeer(),
                    });

                    arena_entries_.push_back(ArenaEntry{
                        .wire_len = wire_len,
                        .dest = session->GetTransport().GetPeer(),
                        .socketFd = socketFd,
                        .session = session,
                    });
                }

                // ---- Flush this chunk via sendmmsg(2) ----
                if (!sendEntries_.empty() && socketFd >= 0)
                {
                    logger_->debug("StartTunReceiver: sending {} encrypted packets to client(s)", sendEntries_.size());
                    auto sent = transport::SendBatch(socketFd, sendEntries_, *batch_scratch_);
                    stats_.packetsSent += sent;
                    for (std::size_t i = 0; i < sent; ++i)
                    {
                        stats_.bytesSent += arena_entries_[i].wire_len;
                        if (arena_entries_[i].session)
                            arena_entries_[i].session->UpdateLastOutbound();
                    }

                    if (sent < sendEntries_.size())
                    {
                        stats_.sendErrors += sendEntries_.size() - sent;
                        logger_->warn("sendmmsg: sent {}/{} datagrams", sent, sendEntries_.size());
                    }
                }

                // Yield to event loop between chunks so other coroutines
                // (UDP receiver for ACKs, keepalive, stats) can make progress
                if (chunk_end < count)
                    co_await asio::post(io_context_, asio::use_awaitable);
            }
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
            {
                logger_->debug("TUN receiver stopped (shutdown)");
                co_return;
            }
            logger_->error("Error reading from TUN: {}", e.what());
        }
        catch (const std::exception &e)
        {
            logger_->error("Error reading from TUN: {}", e.what());
        }
    }

    co_return;
}

bool UserspaceDataChannel::InstallKeys(Connection *session,
                                       const std::vector<uint8_t> &key_material,
                                       openvpn::CipherAlgorithm cipher_algo,
                                       openvpn::HmacAlgorithm hmac_algo,
                                       std::uint8_t key_id,
                                       int lame_duck_seconds)
{
    // Install keys with primary/lame duck key rotation
    bool keys_installed = openvpn::KeyDerivation::InstallKeys(
        session->GetDataChannel(),
        key_material,
        cipher_algo,
        hmac_algo,
        key_id,
        lame_duck_seconds);

    if (keys_installed)
    {
        logger_->info("Data channel session keys installed successfully (key_id={})", key_id);
        session->GetDataChannel().SetCurrentKeyId(key_id);
    }
    else
    {
        logger_->error("Failed to install data channel session keys");
    }

    return keys_installed;
}

asio::awaitable<void> UserspaceDataChannel::SendKeepAlivePing(Connection *session)
{
    if (!session || !session->HasTransport())
    {
        logger_->error("SendKeepAlivePing: session is null or has no transport");
        co_return;
    }

    try
    {
        // Build keepalive payload: compress byte + magic (symmetric with client)
        std::vector<std::uint8_t> ping_payload;
        if (session->UsesCompressionFraming())
        {
            ping_payload.reserve(1 + openvpn::KEEPALIVE_PING_SIZE);
            ping_payload.push_back(openvpn::COMPRESS_NONE);
        }
        else
        {
            ping_payload.reserve(openvpn::KEEPALIVE_PING_SIZE);
        }
        ping_payload.insert(ping_payload.end(),
                            openvpn::KEEPALIVE_PING_PAYLOAD,
                            openvpn::KEEPALIVE_PING_PAYLOAD + openvpn::KEEPALIVE_PING_SIZE);

        auto encrypted = session->GetDataChannel().EncryptPacket(
            ping_payload, session->GetSessionId());

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

std::optional<uint32_t> UserspaceDataChannel::ExtractDestIpv4(const tun::IpPacket &packet)
{
    // IPv4 header minimum size
    if (packet.data.size() < openvpn::IPV4_MIN_HEADER_SIZE)
        return std::nullopt;

    // Verify it's IPv4 (first nibble == 4)
    if (packet.version() != 4)
        return std::nullopt;

    // Destination IPv4 is at bytes 16-19 (in network byte order)
    uint32_t dest_ipv4 = (static_cast<uint32_t>(packet.data[16]) << 24) | (static_cast<uint32_t>(packet.data[17]) << 16) | (static_cast<uint32_t>(packet.data[18]) << 8) | (static_cast<uint32_t>(packet.data[19]));

    return dest_ipv4; // Return in host byte order
}

std::optional<ipv6::Ipv6Address> UserspaceDataChannel::ExtractDestIpv6(const tun::IpPacket &packet)
{
    // IPv6 header minimum size is 40 bytes
    if (packet.data.size() < 40)
        return std::nullopt;

    // Verify it's IPv6 (first nibble == 6)
    if (packet.version() != 6)
        return std::nullopt;

    // Destination IPv6 is at bytes 24-39 (network byte order)
    ipv6::Ipv6Address dest_v6;
    std::memcpy(dest_v6.data(), packet.data.data() + 24, 16);

    return dest_v6;
}

asio::awaitable<void> UserspaceDataChannel::SendToTun(const tun::IpPacket &packet)
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

asio::awaitable<void> UserspaceDataChannel::RunKeepaliveMonitor(DeadPeerCallback on_dead_peer)
{
    logger_->info("Userspace keepalive monitor started: interval={}s, timeout={}s",
                  keepalive_interval_.count(),
                  keepalive_timeout_.count());

    auto last_tick = std::chrono::steady_clock::now();

    while (running_)
    {
        keepalive_timer_.expires_after(keepalive_interval_);
        try
        {
            co_await keepalive_timer_.async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }

        if (!running_)
            break;

        auto now = std::chrono::steady_clock::now();
        auto time_since_last_tick = std::chrono::duration<double>(now - last_tick).count();
        last_tick = now;

        auto session_ids = session_manager_.GetAllSessionIds();
        logger_->debug("Keepalive tick ({:.2f}s): {} active sessions",
                       time_since_last_tick,
                       session_ids.size());

        for (const auto &session_id : session_ids)
        {
            auto *session = session_manager_.FindSession(session_id);
            if (!session)
                continue;

            // Skip sessions without established data channel
            if (!session->GetDataChannel().HasValidKeys())
                continue;

            // Check timeout: if no activity within keepalive_timeout_, peer is dead
            auto last_activity = session->GetLastActivity();
            auto time_since_activity = now - last_activity;
            if (time_since_activity >= keepalive_timeout_)
            {
                double secs = std::chrono::duration<double>(time_since_activity).count();
                logger_->warn("Session {} timed out ({:.1f}s since last activity)", session_id, secs);
                on_dead_peer(session_id);
                continue;
            }

            // Send PING if outbound idle for >= keepalive_interval_
            auto last_outbound = session->GetLastOutbound();
            auto time_since_outbound = now - last_outbound;

            if (time_since_outbound >= keepalive_interval_)
            {
                try
                {
                    co_await SendKeepAlivePing(session);
                    session->UpdateLastOutbound();
                }
                catch (const std::exception &e)
                {
                    logger_->warn("Failed to send keepalive PING to {}: {}", session_id, e.what());
                }
            }
        }
    }
}

void UserspaceDataChannel::StopKeepaliveMonitor()
{
    keepalive_timer_.cancel();
}

} // namespace clv::vpn
