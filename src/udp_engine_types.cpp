// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "udp_engine_types.h"

#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "routing_table.h"
#include "transport/transport.h"

#include <HelpSslCipher.h>
#include <HelpSslException.h>
#include <chrono>
#include <optional>
#include <qsbr_type.h>
#include <util/byte_packer.h>

#include <spdlog/spdlog.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <utility>

namespace clv::vpn {

// ============================================================================
// Local helpers (mirrors of statics in data_channel.cpp)
// ============================================================================

static const OpenSSL::AeadCipherTraits *GetAeadTraits(openvpn::CipherAlgorithm algo)
{
    switch (algo)
    {
    case openvpn::CipherAlgorithm::AES_128_GCM:
        return &OpenSSL::AES_128_GCM_TRAITS;
    case openvpn::CipherAlgorithm::AES_256_GCM:
        return &OpenSSL::AES_256_GCM_TRAITS;
    case openvpn::CipherAlgorithm::CHACHA20_POLY1305:
        return &OpenSSL::CHACHA20_POLY1305_TRAITS;
    default:
        return nullptr;
    }
}

static bool IsSupportedAead(openvpn::CipherAlgorithm algo)
{
    return GetAeadTraits(algo) != nullptr;
}

static std::array<std::uint8_t, 12> GenerateAeadNonce(std::uint32_t packet_id,
                                                      std::span<const std::uint8_t> cipher_iv)
{
    std::array<std::uint8_t, 12> nonce{};
    auto pktid_bytes = clv::netcore::uint_to_bytes(packet_id);
    std::memcpy(nonce.data(), pktid_bytes.data(), 4);
    if (cipher_iv.size() >= 8)
        std::memcpy(nonce.data() + 4, cipher_iv.data(), 8);
    return nonce;
}

// ============================================================================
// SessionIndex
// ============================================================================

const SessionEntry *SessionIndex::Find(openvpn::SessionId id) const
{
    auto it = entries.find(id.value);
    return it != entries.end() ? &it->second : nullptr;
}

const SessionEntry *SessionIndex::FindByEndpoint(const transport::PeerEndpoint &ep) const
{
    auto it = by_endpoint.find(ep);
    if (it == by_endpoint.end())
        return nullptr;
    auto eit = entries.find(it->second);
    return eit != entries.end() ? &eit->second : nullptr;
}

SessionIndex SessionIndex::BuildFrom(const SessionManager &sm)
{
    SessionIndex idx;
    for (auto sid : sm.GetAllSessionIds())
    {
        // FindSession is non-const on SessionManager; cast is safe here because
        // BuildFrom is called from the control plane which owns the SessionManager.
        auto *conn = const_cast<SessionManager &>(sm).FindSession(sid);
        if (!conn)
            continue;

        auto &dc = conn->GetDataChannel();
        if (!dc.HasValidKeys())
            continue;
        if (!conn->HasTransport())
            continue;

        const auto &ekey = dc.GetPrimaryEncryptKey();
        const auto &dkey = dc.GetPrimaryDecryptKey();
        const auto key_id = dc.GetCurrentKeyId();
        // Log first 8 bytes of decrypt/encrypt keys so we can correlate with
        // the auth-fail "slot_key(first8)" log at rekey time.
        {
            const auto &dck = dkey.cipher_key;
            const auto &eck = ekey.cipher_key;
            spdlog::debug("BuildFrom: sid={:016x} key_id={} "
                          "decrypt(first8)={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} "
                          "encrypt(first8)={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                          sid.value,
                          key_id,
                          dck.size() > 0 ? dck[0] : 0,
                          dck.size() > 1 ? dck[1] : 0,
                          dck.size() > 2 ? dck[2] : 0,
                          dck.size() > 3 ? dck[3] : 0,
                          dck.size() > 4 ? dck[4] : 0,
                          dck.size() > 5 ? dck[5] : 0,
                          dck.size() > 6 ? dck[6] : 0,
                          dck.size() > 7 ? dck[7] : 0,
                          eck.size() > 0 ? eck[0] : 0,
                          eck.size() > 1 ? eck[1] : 0,
                          eck.size() > 2 ? eck[2] : 0,
                          eck.size() > 3 ? eck[3] : 0,
                          eck.size() > 4 ? eck[4] : 0,
                          eck.size() > 5 ? eck[5] : 0,
                          eck.size() > 6 ? eck[6] : 0,
                          eck.size() > 7 ? eck[7] : 0);
        }
        auto &ep = conn->GetEndpoint();
        transport::PeerEndpoint peer{.addr = ep.addr, .port = ep.port};
        idx.entries[sid.value] = SessionEntry{
            .conn = conn,
            .encrypt_key = ekey,
            .decrypt_key = dkey,
            .key_id = key_id,
            .endpoint = peer,
        };
        idx.by_endpoint[peer] = sid.value;
    }
    return idx;
}

// ============================================================================
// TxEncryptState
// ============================================================================

bool TxEncryptState::NeedsReinit(std::uint8_t published_key_id) const
{
    return !valid || current_key_id != published_key_id;
}

void TxEncryptState::ApplySnapshot(const openvpn::EncryptionKey &key, std::uint8_t key_id)
{
    current_key_id = key_id;
    cipher_iv = key.cipher_iv;

    if (IsSupportedAead(key.cipher_algorithm))
    {
        encrypt_ctx.emplace();
        const auto *traits = GetAeadTraits(key.cipher_algorithm);
        encrypt_ctx->InitAeadEncrypt(*traits);

        std::array<std::uint8_t, OpenSSL::AEAD_DEFAULT_NONCE_LENGTH> dummy_nonce{};
        encrypt_ctx->SetEncryptKeyAndNonce(key.cipher_key, dummy_nonce);
    }
    else
    {
        encrypt_ctx.reset();
    }

    valid = true;
}

std::size_t TxEncryptState::EncryptInPlace(std::span<std::uint8_t> buf,
                                           std::size_t payload_len,
                                           openvpn::SessionId session_id)
{
    return EncryptInPlace(buf, payload_len, session_id, outbound_packet_id++);
}

std::size_t TxEncryptState::EncryptInPlace(std::span<std::uint8_t> buf,
                                           std::size_t payload_len,
                                           openvpn::SessionId session_id,
                                           std::uint32_t packet_id)
{
    using namespace openvpn;

    if (!valid || !encrypt_ctx)
        return 0;

    const std::size_t total_len = kDataV2Overhead + payload_len;
    if (buf.size() < total_len)
        return 0;

    // P_DATA_V2 header: [opcode/key_id (1)][peer_id (3)] at [0..4)
    std::uint32_t peer_id = session_id.value & PEER_ID_MASK;
    std::uint32_t opcode_peer_id = (MakeOpcodeByte(Opcode::P_DATA_V2, current_key_id) << 24) | peer_id;
    auto hdr_bytes = clv::netcore::uint_to_bytes(opcode_peer_id);
    std::memcpy(buf.data(), hdr_bytes.data(), kDataV2HeaderLen);

    // Packet ID at [4..8)
    auto pktid_bytes = clv::netcore::uint_to_bytes(packet_id);
    std::memcpy(buf.data() + kDataV2HeaderLen, pktid_bytes.data(), kDataV2PacketIdLen);

    // Nonce: packet_id (4 BE) || cipher_iv salt (8)
    auto nonce = GenerateAeadNonce(packet_id, cipher_iv);

    // AAD = first 8 bytes (header + packet_id)
    auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);

    try
    {
        auto plaintext_span = buf.subspan(kDataV2Overhead, payload_len);
        encrypt_ctx->SetEncryptNonce(nonce);
        encrypt_ctx->UpdateEncryptAad(aad);
        encrypt_ctx->UpdateEncryptInPlace(plaintext_span);
        auto tag = encrypt_ctx->FinalizeEncryptTag();

        // Tag at [8..24)
        std::memcpy(buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen,
                    tag.data(),
                    kDataV2TagLen);
    }
    catch (const OpenSSL::SslException &e)
    {
        spdlog::error("TxEncryptState::EncryptInPlace: AEAD encryption failed: {}", e.what());
        return 0;
    }

    return total_len;
}

// ============================================================================
// RxDecryptState
// ============================================================================

bool RxDecryptState::NeedsReinit(std::uint8_t published_key_id) const
{
    return !valid || current_key_id != published_key_id;
}

void RxDecryptState::ApplySnapshot(const RxDecryptSnapshot &snap)
{
    if (!snap.valid)
        return;

    // Move current primary to lame duck if we already had a valid key
    if (valid)
    {
        if (logger)
            logger->debug("RxDecryptState::ApplySnapshot: key_id {} -> {} (old lame_duck key_id={})",
                          current_key_id,
                          snap.key_id,
                          lame_duck ? (int)lame_duck->key.key_id : -1);
        lame_duck.emplace(std::move(primary));
    }

    // Log bytes being installed so we can track what ends up in lame_duck at next rekey.
    {
        const auto &ck = snap.decrypt_key.cipher_key;
        if (logger)
            logger->debug("RxDecryptState::ApplySnapshot: installing key_id={} decrypt(first8)={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                          snap.key_id,
                          ck.size() > 0 ? ck[0] : 0,
                          ck.size() > 1 ? ck[1] : 0,
                          ck.size() > 2 ? ck[2] : 0,
                          ck.size() > 3 ? ck[3] : 0,
                          ck.size() > 4 ? ck[4] : 0,
                          ck.size() > 5 ? ck[5] : 0,
                          ck.size() > 6 ? ck[6] : 0,
                          ck.size() > 7 ? ck[7] : 0);
    }
    // Install new primary decrypt key
    primary = openvpn::DecryptKeySlot{};
    primary.key = snap.decrypt_key;
    primary.replay.Reset();

    // Create persistent AEAD decrypt context
    if (IsSupportedAead(snap.decrypt_key.cipher_algorithm))
    {
        const auto *traits = GetAeadTraits(snap.decrypt_key.cipher_algorithm);
        primary.decrypt_ctx.emplace();
        primary.decrypt_ctx->InitAeadDecrypt(*traits);
        std::array<std::uint8_t, OpenSSL::AEAD_DEFAULT_NONCE_LENGTH> dummy_nonce{};
        primary.decrypt_ctx->SetDecryptKeyAndNonce(snap.decrypt_key.cipher_key, dummy_nonce);
    }

    current_key_id = snap.key_id;
    valid = true;
}

std::span<std::uint8_t> RxDecryptState::DecryptPacketInPlace(std::span<std::uint8_t> buf)
{
    using namespace openvpn;

    if (buf.size() < kDataV2Overhead)
        return {};

    // Parse opcode and key_id from first byte
    std::uint8_t opcode_byte = buf[0];
    auto opcode = static_cast<Opcode>(opcode_byte >> OPCODE_SHIFT);
    std::uint8_t pkt_key_id = opcode_byte & KEY_ID_MASK;

    if (!IsDataPacket(opcode))
        return {};

    // Find matching decrypt slot
    DecryptKeySlot *slot = nullptr;
    if (primary.key.is_valid && primary.key.key_id == pkt_key_id)
    {
        slot = &primary;
    }
    else if (lame_duck && lame_duck->key.is_valid && lame_duck->key.key_id == pkt_key_id)
    {
        slot = &*lame_duck;
    }

    if (!slot)
    {
        auto now = std::chrono::steady_clock::now();
        if (no_key_limiter.Due(now) && logger)
            logger->warn("RxDecryptState: no key found for key_id {}", pkt_key_id);
        return {};
    }

    if (!IsSupportedAead(slot->key.cipher_algorithm) || !slot->decrypt_ctx)
        return {};

    // Extract packet_id from [4..8) (big-endian)
    std::uint32_t pkt_id = (static_cast<std::uint32_t>(buf[4]) << 24)
                           | (static_cast<std::uint32_t>(buf[5]) << 16)
                           | (static_cast<std::uint32_t>(buf[6]) << 8)
                           | static_cast<std::uint32_t>(buf[7]);

    // Anti-replay
    auto replay_check = slot->replay.Check(pkt_id);
    if (replay_check == ReplayWindow::CheckResult::TooOld)
    {
        auto now = std::chrono::steady_clock::now();
        if (too_old_limiter.Due(now) && logger)
            logger->warn("RxDecryptState: packet_id {} too old (highest={})", pkt_id, slot->replay.highest_id());
        replayed_packets++;
        return {};
    }
    if (replay_check == ReplayWindow::CheckResult::Duplicate)
    {
        replayed_packets++;
        return {};
    }

    // Nonce: packet_id (4 BE) || cipher_iv salt (8)
    auto nonce = GenerateAeadNonce(pkt_id, slot->key.cipher_iv);

    // AAD = first 8 bytes
    auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);

    // Tag at [8..24)
    std::span<const std::uint8_t, OpenSSL::AEAD_TAG_LENGTH> tag{
        buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen, kDataV2TagLen};

    // Ciphertext at [24..end)
    std::size_t ct_len = buf.size() - kDataV2Overhead;
    auto ct_span = buf.subspan(kDataV2Overhead, ct_len);

    try
    {
        slot->decrypt_ctx->SetDecryptNonce(nonce);
        slot->decrypt_ctx->UpdateDecryptAad(aad);
        slot->decrypt_ctx->UpdateDecryptInPlace(ct_span);
        bool ok = slot->decrypt_ctx->FinalizeDecryptCheck(tag);

        if (!ok)
        {
            if (logger)
            {
                auto now = std::chrono::steady_clock::now();
                if (auth_fail_limiter.Due(now))
                {
                    auto suppressed = auth_fail_limiter.SuppressedCount();
                    // Format first 8 bytes of cipher key for comparison with DataChannel install log
                    std::string key_hex;
                    const auto &ck = slot->key.cipher_key;
                    for (std::size_t i = 0; i < std::min(ck.size(), std::size_t(8)); ++i)
                    {
                        char buf2[3];
                        std::snprintf(buf2, sizeof(buf2), "%02x", ck[i]);
                        key_hex += buf2;
                    }
                    logger->error("RxDecryptState: authentication failed (tag mismatch) pkt_key_id={} slot_key_id={} is_lame_duck={} current_key_id={} slot_key(first8)={} (+{} suppressed)",
                                  pkt_key_id,
                                  slot->key.key_id,
                                  slot != &primary,
                                  current_key_id,
                                  key_hex,
                                  suppressed);
                }
            }
            return {};
        }

        slot->replay.Accept(pkt_id);
        return ct_span;
    }
    catch (const OpenSSL::SslException &e)
    {
        if (logger)
            logger->error("RxDecryptState: AEAD decryption failed: {}", e.what());
        return {};
    }
}

// ============================================================================
// DeferredConnection (defined here where Connection is complete)
// ============================================================================

DeferredConnection::DeferredConnection(std::unique_ptr<Connection> c, std::uint64_t e)
    : conn(std::move(c)), epoch(e)
{
}
DeferredConnection::~DeferredConnection() = default;
DeferredConnection::DeferredConnection(DeferredConnection &&) noexcept = default;
DeferredConnection &DeferredConnection::operator=(DeferredConnection &&) noexcept = default;

// ============================================================================
// UdpEngineContext
// ============================================================================

UdpEngineContext::UdpEngineContext()
    : core(std::make_shared<QsbrCore>()), routes_v4(core, RoutingTableIpv4{}), routes_v6(core, RoutingTableIpv6{}), sessions(core, SessionIndex{}), sessions_rx(core, SessionIndex{})
{
}

UdpEngineContext::~UdpEngineContext() = default;

void UdpEngineContext::PublishRoutes(const RoutingTableIpv4 &v4,
                                     const RoutingTableIpv6 &v6)
{
    routes_v4.write(v4);
    routes_v6.write(v6);
}

void UdpEngineContext::PublishSessions(const SessionIndex &idx)
{
    sessions.write(idx);
    sessions_rx.write(idx); // keep in sync with TX snapshot
}

void UdpEngineContext::PublishSessions(const SessionManager &sm)
{
    auto idx = SessionIndex::BuildFrom(sm);
    sessions.write(idx);
    sessions_rx.write(idx); // keep in sync with TX snapshot
}

void UdpEngineContext::PublishSessionsRx(const SessionManager &sm)
{
    // Publish decrypt keys to RX thread immediately (before ACK).
    // TX snapshot (sessions) is not touched here — TX stays on the old key
    // until SplitPublishSessions() is called after the client ACKs KEY_METHOD_2.
    sessions_rx.write(SessionIndex::BuildFrom(sm));
}

void UdpEngineContext::DeferDestruction(std::unique_ptr<Connection> conn)
{
    auto epoch = core->begin_grace_period();
    deferred.emplace_back(std::move(conn), epoch);
}

void UdpEngineContext::ReclaimDeferred()
{
    if (!cp_registered_)
    {
        core->register_thread();
        cp_registered_ = true;
    }
    std::erase_if(deferred, [this](DeferredConnection &d)
    {
        if (core->can_reclaim(d.epoch))
        {
            d.conn.reset(); // destroy the Connection
            return true;
        }
        return false;
    });
}

void UdpEngineContext::ForceReclaimAll()
{
    // Force-delete all retired pointers for this QsbrCore that are sitting in
    // this thread's retired_list.  Safe because all data-path readers have
    // already stopped by the time this is called.
    routes_v4.force_reclaim_for_core();
    routes_v6.force_reclaim_for_core();
    sessions.force_reclaim_for_core();

    // Unregister this thread from the underlying QSBR system.  This frees
    // the posix_memalign allocation made by qsbr_register() in ReclaimDeferred().
    if (cp_registered_)
    {
        core->unregister_thread();
        cp_registered_ = false;
    }
}

} // namespace clv::vpn
