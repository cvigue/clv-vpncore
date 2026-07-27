// Copyright (c) 2025- Charlie Vigue. All rights reserved.

// Design note: This file uses defensive programming with explicit validation and
// detailed error logging. The control channel handles connection setup and key
// renegotiation - infrequent operations where debuggability matters more than
// micro-optimization. The data channel (P_DATA_V2) is the hot path.

#include "openvpn/control_channel.h"

#include "openvpn/control_channel_fragment.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/tls_context.h"

#include <log_utils.h>
#include <numeric_util.h>

#include <spdlog/spdlog.h>

#include <netinet/in.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

void ControlChannel::Reset()
{
    state_ = State::Disconnected;
    session_id_ = {};
    peer_session_id_.reset();
    tls_context_.reset();
    key_id_ = 0;
    outbound_packet_id_ = 0;
    last_received_packet_id_ = UINT32_MAX;
    pending_acks_.clear();
    in_flight_acks_.clear();
    reack_candidates_.clear();
    unacked_packets_.clear();
    tls_buffer_.clear();
    is_client_ = false;
    pending_fragments_.clear();
    received_plaintext_.clear();
}

bool ControlChannel::Initialize(PeerRole role,
                                SessionId initial_session_id,
                                std::optional<TlsCertConfig> cert_config)
{
    if (state_ != State::Disconnected || tls_context_)
        return false;

    session_id_ = initial_session_id;
    is_client_ = (role == PeerRole::Client);
    tls_context_.emplace(role, cert_config, *logger_);
    state_ = State::Disconnected; // Ready for handshake

    return true;
}

std::vector<std::uint8_t> ControlChannel::StartHardReset(std::uint8_t key_id_arg)
{
    if (state_ != State::Disconnected && state_ != State::Error)
        return {};

    key_id_ = key_id_arg & KEY_ID_MASK;
    is_client_ = true;
    state_ = State::HardResetPending;

    return SendHardReset(key_id_, true);
}

std::vector<std::uint8_t> ControlChannel::SendHardReset(std::uint8_t key_id, bool is_client)
{
    auto packet = OpenVpnPacket::HardReset(is_client, 3 /* v3/tls-crypt */, key_id, session_id_.value, GetNextPacketId());

    auto serialized = packet.Serialize();
    if (!serialized.empty() && packet.packet_id_)
        TrackOutboundPacket(packet.packet_id_.value(), serialized);

    return serialized;
}

bool ControlChannel::HandleHardReset(const OpenVpnPacket &packet)
{
    if (!tls_context_)
        return false;

    if (!packet.IsHardReset())
    {
        logger_->warn("HandleHardReset: invalid opcode {}", static_cast<int>(packet.opcode_));
        return false;
    }

    // Save peer's session ID
    if (packet.session_id_)
        peer_session_id_ = SessionId{packet.session_id_.value()};

    // Set key ID from incoming packet
    key_id_ = packet.key_id_;

    if (packet.packet_id_)
    {
        // Track incoming packet for ACKing if packet ID present
        logger_->debug("HandleHardReset: packet_id={}, pending_acks.size={}", packet.packet_id_.value(), pending_acks_.size());
        last_received_packet_id_ = packet.packet_id_.value();
        pending_acks_.push_back(packet.packet_id_.value());
    }
    else
        logger_->debug("HandleHardReset: packet_id=(none), pending_acks.size={}", pending_acks_.size());

    // Transition to TLS handshake state
    if (state_ == State::Disconnected || state_ == State::HardResetPending)
    {
        state_ = State::TlsHandshake;
        return true;
    }

    logger_->warn("HandleHardReset: rejected - wrong state {} (need Disconnected or HardResetPending)",
                  static_cast<int>(state_));

    return false;
}

bool ControlChannel::CompleteCookieHandshake(SessionId peer_session_id, std::uint8_t key_id)
{
    if (!tls_context_)
        return false;
    if (state_ != State::Disconnected && state_ != State::HardResetPending)
    {
        logger_->warn("CompleteCookieHandshake: rejected - wrong state {}", static_cast<int>(state_));
        return false;
    }

    peer_session_id_ = peer_session_id;
    key_id_ = key_id & KEY_ID_MASK;
    // Stateless cookie challenge already used control packet_id 0 outbound.
    outbound_packet_id_ = 1;
    // Next CONTROL may be packet_id 0 (cookie-echo ClientHello) or 1 (typical
    // OpenVPN after HARD_RESET was pid 0). UINT32_MAX + ValidatePacketId
    // accepts either; first accepted packet advances last_received normally.
    last_received_packet_id_ = UINT32_MAX;
    state_ = State::TlsHandshake;
    return true;
}

void ControlChannel::AdvanceRekeyKeyId()
{
    // Per OpenVPN protocol: key_id 0 is always the first session. Renegotiations
    // use key_id 1-7, then wrap back to 1 (not 0). See OpenVPN ssl.c:830-844
    const std::uint8_t old_key_id = key_id_;
    std::uint8_t new_key_id = (key_id_ + 1) & 0x07;
    if (new_key_id == 0)
        new_key_id = 1;
    logger_->debug("AdvanceRekeyKeyId: key_id {} -> {}", old_key_id, new_key_id);
    key_id_ = new_key_id;
}

void ControlChannel::ResetReliabilityForRekey(bool reset_inbound_to_max)
{
    // Session IDs stay the same across soft reset.
    outbound_packet_id_ = 0;
    unacked_packets_.clear();
    // Defense-in-depth: drop already-serialized fragments so they cannot flush
    // under the new key_id (cve-audit F2 / CVE-2026-40215 hygiene).
    pending_fragments_.clear();
    if (reset_inbound_to_max)
    {
        // UINT32_MAX sentinel: ValidatePacketId accepts packet_id 0 as first.
        last_received_packet_id_ = UINT32_MAX;
    }
}

void ControlChannel::EmplaceTlsForRekey(PeerRole role, const TlsCertConfig &cert_config)
{
    try
    {
        tls_context_.emplace(role, cert_config, *logger_);
    }
    catch (const std::exception &e)
    {
        logger_->error("EmplaceTlsForRekey: failed to reinitialize TLS context: {}", e.what());
        state_ = State::Error;
        throw;
    }
    received_plaintext_.clear();
    state_ = State::TlsHandshake;
}

std::vector<std::uint8_t> ControlChannel::HandleSoftReset(const OpenVpnPacket &packet, const TlsCertConfig &cert_config)
{
    if (!packet.IsSoftReset())
    {
        logger_->warn("HandleSoftReset: invalid opcode {}", static_cast<int>(packet.opcode_));
        return {};
    }

    // If we're already in TlsHandshake state the server initiated this renegotiation and
    // the client is echoing our P_CONTROL_SOFT_RESET_V1 back (or retransmitting it).
    // Do NOT reinitialize TLS or advance key_id — just ACK and let the TLS ClientHello
    // arrive next.  We MUST update last_received_packet_id_ here so that ValidatePacketId
    // accepts the client's subsequent P_CONTROL_V1 (packet_id = this + 1).
    if (state_ == State::TlsHandshake)
    {
        logger_->debug("HandleSoftReset: server-initiated rekey — client soft-reset echo received, ACKing");

        if (packet.packet_id_)
        {
            last_received_packet_id_ = packet.packet_id_.value();
            pending_acks_.push_back(packet.packet_id_.value());
        }

        return GenerateExplicitAck();
    }

    // Soft reset can only occur when in Active or KeyMaterialReady state
    // (connection must be established with keys installed)
    if (state_ != State::Active && state_ != State::KeyMaterialReady)
    {
        logger_->warn("HandleSoftReset: rejected - wrong state {} (need Active or KeyMaterialReady)",
                      static_cast<int>(state_));
        return {};
    }

    logger_->info("HandleSoftReset: starting key renegotiation (from state {})", static_cast<int>(state_));

    // Track incoming packet for ACKing
    if (packet.packet_id_)
    {
        last_received_packet_id_ = packet.packet_id_.value();
        pending_acks_.push_back(packet.packet_id_.value());
    }

    AdvanceRekeyKeyId();
    ResetReliabilityForRekey(/*reset_inbound_to_max=*/false);
    // VPN server is always the TLS server regardless of who initiated soft reset.
    EmplaceTlsForRekey(PeerRole::Server, cert_config);

    // ACK the peer's soft reset.  The VPN server waits for the remote client's
    // ClientHello (which arrives as P_CONTROL_V1 packets).
    return GenerateExplicitAck();
}

std::vector<std::uint8_t> ControlChannel::GenerateHardResetResponse(Opcode client_opcode)
{
    // Validate client opcode - must be a hard reset client packet
    if (!IsHardResetClient(client_opcode))
        return {};

    uint32_t our_packet_id = GetNextPacketId();
    logger_->debug("GenerateHardResetResponse: our_packet_id={}", our_packet_id);

    auto response_packet = OpenVpnPacket::HardResetResponse(client_opcode, key_id_, session_id_.value, our_packet_id);

    // Piggyback ACKs if we have peer session and pending ACKs
    if (peer_session_id_)
    {
        auto acks_to_send = CollectAcksForPiggyback();
        if (!acks_to_send.empty())
        {
            response_packet.withAcks(acks_to_send, peer_session_id_->value);
            logger_->debug("GenerateHardResetResponse: piggybacking {} ACKs", acks_to_send.size());
            RecordInFlightAcks(our_packet_id, acks_to_send);
        }
    }

    auto serialized = response_packet.Serialize();
    if (!serialized.empty())
    {
        logger_->debug("Hard reset response packet serialized: {} bytes", serialized.size());
        TrackOutboundPacket(our_packet_id, serialized);
    }

    return serialized;
}

std::vector<std::uint8_t> ControlChannel::GenerateExplicitAck()
{
    if (pending_acks_.empty() && reack_candidates_.empty())
        return {};

    if (!peer_session_id_)
    {
        logger_->error("GenerateExplicitAck: have {} pending ACKs but no peer_session_id", pending_acks_.size());
        return {};
    }

    // Use CollectAcksForPiggyback to properly limit to MAX_ACK_COUNT (8)
    // and include reack_candidates_. Caller should call again if more remain.
    auto acks_to_send = CollectAcksForPiggyback();
    if (acks_to_send.empty())
        return {};

    auto ack_packet = OpenVpnPacket::Ack(key_id_,
                                         session_id_.value,
                                         peer_session_id_->value,
                                         std::move(acks_to_send));

    return ack_packet.Serialize();
}

std::vector<std::uint8_t> ControlChannel::GenerateWkcResendPacket()
{
    if (!peer_session_id_)
    {
        logger_->error("GenerateWkcResendPacket: no peer_session_id");
        return {};
    }

    // Do not TrackOutboundPacket: the caller appends WKc after tls-crypt wrap,
    // so a reliability retransmit of the plaintext would omit WKc. If the WKC
    // is lost, the client's HARD_RESET retransmit restarts the cookie exchange.
    const std::uint32_t packet_id = GetNextPacketId();
    auto acks_to_send = CollectAcksForPiggyback();

    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_CONTROL_WKC_V1;
    pkt.key_id_ = key_id_ & KEY_ID_MASK;
    pkt.session_id_ = session_id_.value;
    pkt.packet_id_ = packet_id;
    pkt.payload_ = {};
    if (!acks_to_send.empty())
        pkt.withAcks(acks_to_send, peer_session_id_->value);

    return pkt.Serialize();
}

bool ControlChannel::PromoteToKeyMaterialReady()
{
    if (state_ != State::TlsHandshake || !tls_context_ || !tls_context_->IsHandshakeComplete())
        return false;
    state_ = State::KeyMaterialReady;
    return true;
}

std::optional<std::vector<std::uint8_t>> ControlChannel::InitiateTlsHandshake()
{
    logger_->debug("InitiateTlsHandshake called, state={}", static_cast<int>(state_));

    if (state_ != State::TlsHandshake || !tls_context_)
    {
        logger_->error("InitiateTlsHandshake: wrong state or no TLS context");
        return std::nullopt;
    }

    // For server-side, initiate the handshake by calling ProcessIncomingData with empty data
    // This triggers the server to generate ServerHello
    auto tls_response = tls_context_->ProcessIncomingData({});

    if (!tls_response)
    {
        logger_->error("Failed to initiate TLS handshake");
        state_ = State::Error;
        return std::nullopt;
    }

    logger_->debug("TLS response size: {} bytes", tls_response->size());

    // If we have TLS data to send, wrap it in a control packet
    if (tls_response->empty())
        return std::vector<std::uint8_t>();

    uint32_t packet_id = GetNextPacketId();
    auto response = OpenVpnPacket::Control(key_id_, session_id_.value, packet_id, *tls_response);

    auto serialized = response.Serialize();
    if (!serialized.empty())
        TrackOutboundPacket(packet_id, serialized);

    return serialized;
}

std::vector<std::uint8_t> ControlChannel::RequestSoftReset(PeerRole role, const TlsCertConfig &cert_config)
{
    if (state_ != State::Active && state_ != State::KeyMaterialReady)
        return {};

    logger_->info("RequestSoftReset: initiating key renegotiation as TLS {}",
                  role == PeerRole::Server ? "server" : "client");

    AdvanceRekeyKeyId();
    // Local initiator: peer will restart from packet_id 0.
    ResetReliabilityForRekey(/*reset_inbound_to_max=*/true);
    EmplaceTlsForRekey(role, cert_config);

    auto packet = OpenVpnPacket::SoftReset(key_id_, session_id_.value, GetNextPacketId());

    auto serialized = packet.Serialize();
    if (!serialized.empty() && packet.packet_id_)
        TrackOutboundPacket(packet.packet_id_.value(), serialized);

    return serialized;
}

std::vector<std::uint8_t> ControlChannel::RespondToSoftReset(const OpenVpnPacket &packet, const TlsCertConfig &cert_config)
{
    if (!packet.IsSoftReset())
    {
        logger_->warn("RespondToSoftReset: invalid opcode {}", static_cast<int>(packet.opcode_));
        return {};
    }

    // Already mid-renegotiation — just re-ACK (retransmit from server).
    if (state_ == State::TlsHandshake)
    {
        logger_->debug("RespondToSoftReset: already renegotiating, sending ACK for retransmit");
        if (packet.packet_id_)
            pending_acks_.push_back(packet.packet_id_.value());
        return GenerateExplicitAck();
    }

    if (state_ != State::Active && state_ != State::KeyMaterialReady)
    {
        logger_->warn("RespondToSoftReset: rejected - wrong state {} (need Active or KeyMaterialReady)",
                      static_cast<int>(state_));
        return {};
    }

    logger_->info("RespondToSoftReset: starting key renegotiation in response to server soft reset");

    // Record incoming packet for ACKing.
    if (packet.packet_id_)
    {
        last_received_packet_id_ = packet.packet_id_.value();
        pending_acks_.push_back(packet.packet_id_.value());
    }

    AdvanceRekeyKeyId();
    ResetReliabilityForRekey(/*reset_inbound_to_max=*/false);
    EmplaceTlsForRekey(PeerRole::Client, cert_config);

    // ACK the server's soft reset.  The client will follow up with
    // InitiateTlsHandshake() → ClientHello via the normal TLS data path.
    // We must NOT echo back P_CONTROL_SOFT_RESET_V1; the server is already
    // in TlsHandshake state waiting for ClientHello, and receiving another
    // soft reset would be rejected or cause state confusion.
    return GenerateExplicitAck();
}

std::optional<std::vector<std::vector<std::uint8_t>>> ControlChannel::ProcessTlsData(const OpenVpnPacket &control_packet)
{
    // Preconditions (class invariants)
    assert(!control_packet.IsHardReset() && "Hard reset packets must be handled by HandleHardReset()");
    assert(tls_context_ && "TLS context must exist when ProcessTlsData is called");

    logger_->debug("ProcessTlsData: opcode={}, state={}, payload={} bytes, packet_id={}",
                   static_cast<int>(control_packet.opcode_),
                   static_cast<int>(state_),
                   control_packet.payload_.size(),
                   control_packet.packet_id_ ? std::to_string(*control_packet.packet_id_) : "(none)");

    // --- Validation ---
    if (state_ != State::TlsHandshake && state_ != State::KeyMaterialReady)
    {
        logger_->debug("  Rejected: wrong state");
        return std::nullopt;
    }

    if (!IsControlPacket(control_packet.opcode_))
    {
        logger_->debug("  Rejected: not a control packet");
        return std::nullopt;
    }

    if (!control_packet.packet_id_)
    {
        logger_->debug("  Rejected: missing packet_id");
        return std::nullopt;
    }

    if (!ValidatePacketId(control_packet.packet_id_.value()))
    {
        logger_->debug("  Rejected: packet_id {} <= last_received {}",
                       control_packet.packet_id_.value(),
                       last_received_packet_id_);
        return std::nullopt;
    }

    logger_->debug("  Accepted packet_id: {}", control_packet.packet_id_.value());
    logger_->debug("  TLS data size: {}", control_packet.payload_.size());

    // --- Route based on handshake state ---
    auto result = tls_context_->IsHandshakeComplete()
                      ? ProcessPostHandshakeAppData(control_packet.payload_)
                      : ProcessTlsHandshakeData(control_packet.payload_);

    // --- Track for ACK only after processing succeeded ---
    if (result.has_value())
    {
        last_received_packet_id_ = control_packet.packet_id_.value();
        pending_acks_.push_back(control_packet.packet_id_.value());
    }

    return result;
}

std::vector<std::vector<std::uint8_t>> ControlChannel::PrepareTlsEncryptedData(std::span<const std::uint8_t> plaintext)
{
    if (state_ != State::Active && state_ != State::KeyMaterialReady)
    {
        logger_->error("PrepareTlsEncryptedData: wrong state {}", static_cast<int>(state_));
        return {};
    }

    if (!tls_context_ || !tls_context_->IsHandshakeComplete())
    {
        logger_->error("PrepareTlsEncryptedData: TLS handshake not complete");
        return {};
    }

    // Encrypt the plaintext through TLS
    if (int written = tls_context_->WriteAppData(plaintext); written <= 0)
    {
        logger_->error("PrepareTlsEncryptedData: WriteAppData failed");
        return {};
    }

    // Get encrypted TLS records from the BIO
    auto tls_records = tls_context_->GetPendingData();

    if (tls_records.empty())
    {
        logger_->error("PrepareTlsEncryptedData: no TLS output generated");
        return {};
    }

    logger_->debug("PrepareTlsEncryptedData: {} bytes plaintext -> {} bytes TLS",
                   plaintext.size(),
                   tls_records.size());

    // For small messages like PUSH_REPLY, usually fits in one packet
    // Create a single control packet with the TLS data
    std::vector<std::vector<std::uint8_t>> result;

    uint32_t packet_id = GetNextPacketId();
    auto serialized = CreateControlPacketWithAcks(std::move(tls_records), packet_id);
    if (!serialized.empty())
    {
        logger_->debug("PrepareTlsEncryptedData: created packet_id={}", packet_id);
        result.push_back(std::move(serialized));
    }

    return result;
}

bool ControlChannel::HandleAck(const OpenVpnPacket &packet)
{
    if (!packet.IsAck())
        return false;

    ApplyAckIds(packet.packet_id_array_);
    return true;
}

void ControlChannel::ApplyAckIds(std::span<const std::uint32_t> ack_ids)
{
    if (ack_ids.empty())
        return;

    if (logger_->should_log(spdlog::level::debug))
    {
        std::string ack_list;
        for (auto ack_id : ack_ids)
            ack_list += std::to_string(ack_id) + " ";
        logger_->debug("ApplyAckIds: Received ACK for {} packet(s): {}", ack_ids.size(), ack_list);
    }

    for (auto ack_id : ack_ids)
    {
        auto it = unacked_packets_.find(ack_id);
        if (it != unacked_packets_.end())
        {
            logger_->debug("  Marked packet {} as acknowledged", ack_id);
            it->second.MarkAcknowledged();
            ClearInFlightAcks(ack_id);
        }
        else if (ack_id >= outbound_packet_id_)
        {
            logger_->warn("  WARNING: ACK for unsent packet {} (next_id={})", ack_id, outbound_packet_id_);
        }
    }

    // Drop acknowledged entries so CountUnacknowledgedPackets / send window update now
    std::erase_if(unacked_packets_, [](const auto &entry)
    { return entry.second.IsAcknowledged(); });
}

std::vector<std::vector<std::uint8_t>>
ControlChannel::ProcessRetransmissions(std::chrono::steady_clock::time_point now)
{
    std::vector<std::vector<std::uint8_t>> retransmit_list;

    for (auto &[packet_id, tracker] : unacked_packets_)
    {
        if (tracker.ShouldRetransmit(now))
        {
            // On first retransmit, rescue any piggybacked ACKs for re-acking
            if (tracker.RetransmitCount() == 0)
                RescueInFlightAcks(packet_id);
            retransmit_list.push_back(tracker.NoteRetransmission(now));

            // Log retransmission with escalating severity
            if (tracker.RetransmitCount() >= 10)
                logger_->warn("Retransmitting packet_id={} (attempt {}/{}) - connection may be degraded",
                              packet_id,
                              tracker.RetransmitCount(),
                              AckTracker::MAX_RETRANSMIT_ATTEMPTS);
            else
                logger_->info("Retransmitting packet_id={} (attempt {}, RTO={}ms)",
                              packet_id,
                              tracker.RetransmitCount(),
                              tracker.CurrentRetransmitTimeout().count());
        }
    }

    // Clean up acknowledged and expired packets
    std::vector<std::uint32_t> to_erase;
    for (const auto &[packet_id, tracker] : unacked_packets_)
    {
        if (tracker.IsAcknowledged())
        {
            to_erase.push_back(packet_id);
        }
        else if (tracker.ExhaustedRetransmits())
        {
            logger_->error("Packet {} abandoned after {} retransmit attempts - peer unreachable?",
                           packet_id,
                           tracker.RetransmitCount());
            to_erase.push_back(packet_id);
        }
    }

    for (auto packet_id : to_erase)
    {
        unacked_packets_.erase(packet_id);
    }

    return retransmit_list;
}

void ControlChannel::TrackOutboundPacket(std::uint32_t packet_id, std::span<const std::uint8_t> data)
{
    unacked_packets_.emplace(packet_id, AckTracker(packet_id, data));
}

bool ControlChannel::ValidatePacketId(std::uint32_t packet_id)
{
    // UINT32_MAX means no packets received yet. Accept 0 or 1 so cookie-echo
    // ClientHello (pid 0) and the common post-HARD_RESET ClientHello (pid 1)
    // both pass. Subsequent packets must be strictly greater than last received.
    if (last_received_packet_id_ == UINT32_MAX)
        return packet_id <= 1;
    return packet_id > last_received_packet_id_;
}

size_t ControlChannel::CountUnacknowledgedPackets() const
{
    // This could be optimized with a separate counter if needed but the list is very small
    // in practice and control packets are infrequent.
    return std::ranges::count_if(unacked_packets_, [](const auto &pair)
    {
        return !pair.second.IsAcknowledged();
    });
}

std::optional<std::chrono::steady_clock::time_point> ControlChannel::EarliestRetransmitAt() const
{
    std::optional<std::chrono::steady_clock::time_point> earliest;
    for (const auto &[packet_id, tracker] : unacked_packets_)
    {
        (void)packet_id;
        if (tracker.IsAcknowledged() || tracker.ExhaustedRetransmits())
            continue;
        const auto next = tracker.NextRetransmitAt();
        if (!earliest || next < *earliest)
            earliest = next;
    }
    return earliest;
}

std::vector<std::vector<std::uint8_t>> ControlChannel::GetPacketsToSend()
{
    std::vector<std::vector<std::uint8_t>> packets;

    size_t unacked_count = CountUnacknowledgedPackets();
    size_t available_window = (unacked_count < MAX_SEND_WINDOW) ? (MAX_SEND_WINDOW - unacked_count) : 0;

    logger_->debug("GetPacketsToSend: unacked={} window={} available={} queued={}",
                   unacked_count,
                   MAX_SEND_WINDOW,
                   available_window,
                   pending_fragments_.size());

    while (available_window > 0 && !pending_fragments_.empty())
    {
        auto pending = std::move(pending_fragments_.front());
        pending_fragments_.pop_front();
        TrackOutboundPacket(pending.packet_id, pending.data);
        packets.push_back(std::move(pending.data));
        --available_window;
    }

    logger_->debug("  Sending {} packet(s), {} remaining in queue", packets.size(), pending_fragments_.size());

    return packets;
}

std::vector<std::uint8_t> ControlChannel::ReadPlaintext()
{
    std::vector<std::uint8_t> result;
    result.swap(received_plaintext_);
    return result;
}

std::vector<std::uint32_t> ControlChannel::CollectAcksForPiggyback()
{
    std::vector<std::uint32_t> collected;
    collected.reserve(OpenVpnPacket::MAX_ACK_COUNT);

    // Pull from reack_candidates_ first (one re-ack attempt only)
    while (collected.size() < OpenVpnPacket::MAX_ACK_COUNT && !reack_candidates_.empty())
    {
        collected.push_back(reack_candidates_.front());
        reack_candidates_.pop_front();
    }

    // Then pull from pending_acks_
    while (collected.size() < OpenVpnPacket::MAX_ACK_COUNT && !pending_acks_.empty())
    {
        collected.push_back(pending_acks_.front());
        pending_acks_.pop_front();
    }

    return collected;
}

void ControlChannel::RecordInFlightAcks(std::uint32_t packet_id, std::span<const std::uint32_t> acks)
{
    if (!acks.empty())
    {
        in_flight_acks_[packet_id] = std::vector<std::uint32_t>(acks.begin(), acks.end());
    }
}

void ControlChannel::ClearInFlightAcks(std::uint32_t packet_id)
{
    in_flight_acks_.erase(packet_id);
}

void ControlChannel::RescueInFlightAcks(std::uint32_t packet_id)
{
    if (auto it = in_flight_acks_.find(packet_id); it != in_flight_acks_.end())
    {
        // Move these ACKs to reack_candidates for one more try
        for (auto ack_id : it->second)
        {
            reack_candidates_.push_back(ack_id);
        }
        in_flight_acks_.erase(it);
    }
}

std::optional<std::vector<std::vector<std::uint8_t>>> ControlChannel::ProcessTlsHandshakeData(
    std::span<const std::uint8_t> payload)
{
    auto tls_response = tls_context_->ProcessIncomingData(payload);

    if (!tls_response)
    {
        logger_->error("TLS handshake failed");
        state_ = State::Error;
        return std::nullopt;
    }

    logger_->debug("  TLS handshake complete: {}", tls_context_->IsHandshakeComplete() ? "yes" : "no");

    // --- State transition ---
    if (PromoteToKeyMaterialReady())
        logger_->debug("TLS handshake complete!");

    // --- Fragment and queue response ---
    if (tls_response->empty())
        return std::vector<std::vector<std::uint8_t>>();

    auto fragments = FragmentTlsResponse(*tls_response);
    if (fragments.empty())
        return std::vector<std::vector<std::uint8_t>>();

    // Send as many as the reliability window allows; queue the rest untracked
    // until GetPacketsToSend dequeues them (after peer ACKs free window slots).
    size_t unacked_count = CountUnacknowledgedPackets();
    size_t available = (unacked_count < MAX_SEND_WINDOW) ? (MAX_SEND_WINDOW - unacked_count) : 0;
    if (available == 0)
        available = 1; // always make progress on a fresh TLS response

    std::vector<std::vector<std::uint8_t>> to_send;
    to_send.reserve(std::min(fragments.size(), available));

    for (size_t i = 0; i < fragments.size(); ++i)
    {
        if (to_send.size() < available)
        {
            TrackOutboundPacket(fragments[i].packet_id, fragments[i].data);
            to_send.push_back(std::move(fragments[i].data));
        }
        else
        {
            pending_fragments_.push_back(std::move(fragments[i]));
        }
    }

    logger_->debug("  Sending {} TLS fragment(s) immediately, queued {}",
                   to_send.size(),
                   pending_fragments_.size());
    return to_send;
}

std::optional<std::vector<std::vector<std::uint8_t>>>
ControlChannel::ProcessPostHandshakeAppData(std::span<const std::uint8_t> payload)
{
    logger_->debug("  Post-handshake data - decrypting application data");

    // Feed encrypted data to TLS input BIO
    if (!tls_context_->FeedEncryptedData(payload))
    {
        logger_->error("Failed to feed encrypted data to TLS");
        return std::nullopt;
    }

    // Read decrypted plaintext
    if (auto plaintext = tls_context_->ReadAppData(); !plaintext.empty())
    {
        logger_->debug("  Decrypted {} bytes of application data", plaintext.size());
        if (logger_ && logger_->should_log(spdlog::level::trace))
        {
            logger_->trace("  First 20 bytes: {}", HexDump(plaintext, 20));
        }
        // Append to received plaintext buffer
        received_plaintext_.insert(received_plaintext_.end(), plaintext.begin(), plaintext.end());
    }

    // Return empty result (no TLS response needed for app data)
    return std::vector<std::vector<std::uint8_t>>();
}

std::vector<std::uint8_t> ControlChannel::CreateControlPacketWithAcks(std::vector<std::uint8_t> payload,
                                                                      std::uint32_t packet_id,
                                                                      bool track)
{
    auto pkt = OpenVpnPacket::Control(key_id_, session_id_.value, packet_id, std::move(payload));

    // Piggyback ACKs if we have peer session and pending ACKs
    if (peer_session_id_)
    {
        auto acks_to_send = CollectAcksForPiggyback();
        if (!acks_to_send.empty())
        {
            pkt.withAcks(acks_to_send, peer_session_id_->value);
            if (logger_->should_log(spdlog::level::debug))
            {
                std::string ack_list;
                for (auto ack_id : acks_to_send)
                    ack_list += std::to_string(ack_id) + " ";
                logger_->debug("  Piggybacking {} ACKs: {}", acks_to_send.size(), ack_list);
            }
            RecordInFlightAcks(packet_id, acks_to_send);
        }
    }

    auto serialized = pkt.Serialize();
    if (!serialized.empty())
    {
        if (track)
            TrackOutboundPacket(packet_id, serialized);
        logger_->debug("  Created packet_id={}: {} bytes payload (track={})",
                       packet_id,
                       pkt.payload_.size(),
                       track);
    }

    return serialized;
}

std::vector<ControlChannel::PendingOutbound>
ControlChannel::FragmentTlsResponse(std::span<const std::uint8_t> tls_data)
{
    constexpr size_t CONTROL_PAYLOAD_MTU = 1250;

    auto [groups, truncated] = detail::GroupTlsRecords(tls_data, CONTROL_PAYLOAD_MTU);

    if (truncated)
        logger_->error("ERROR: Malformed TLS record encountered during fragmentation");

    std::vector<PendingOutbound> result;
    result.reserve(groups.size());

    for (auto &group : groups)
    {
        uint32_t packet_id = GetNextPacketId();
        // Do not track yet — caller tracks only fragments that enter the send window.
        auto serialized = CreateControlPacketWithAcks(std::move(group), packet_id, /*track=*/false);
        if (!serialized.empty())
        {
            logger_->debug("  Fragment {}: packet_id={}", result.size(), packet_id);
            result.push_back(PendingOutbound{packet_id, std::move(serialized)});
        }
    }

    logger_->debug("  Split {} bytes into {} fragments", tls_data.size(), result.size());
    return result;
}

} // namespace clv::vpn::openvpn
