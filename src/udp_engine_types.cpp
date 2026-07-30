// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "udp_engine_types.h"

#include "openvpn/connection.h"
#include "openvpn/aead_traits.h"
#include "openvpn/crypto_log.h"
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_decrypt.h"
#include "openvpn/data_v2_encrypt.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "routing_table.h"
#include "transport/transport.h"

#include <HelpSslCipher.h>
#include <HelpSslException.h>
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

        auto &dc = conn->GetCryptoContext();
        if (!dc.HasValidKeys())
            continue;
        if (!conn->HasTransport())
            continue;

        const auto &ekey = dc.GetPrimaryEncryptKey();
        const auto &dkey = dc.GetPrimaryDecryptKey();
        const auto key_id = dc.GetCurrentKeyId();
        spdlog::debug("BuildFrom: sid={:016x} key_id={} decrypt_key_fp={} encrypt_key_fp={}",
                      sid.value,
                      key_id,
                      openvpn::KeyMaterialFingerprint(dkey.cipher_key),
                      openvpn::KeyMaterialFingerprint(ekey.cipher_key));
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
    cipher_algorithm = key.cipher_algorithm;
    cipher_iv = key.cipher_iv;

    if (openvpn::IsSupportedAead(key.cipher_algorithm))
    {
        encrypt_ctx.emplace();
        const auto *traits = openvpn::GetAeadTraits(key.cipher_algorithm);
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
                                           openvpn::SessionId session_id,
                                           std::uint32_t packet_id)
{
    if (!valid || !encrypt_ctx)
        return 0;

    const std::size_t total_len = openvpn::kDataV2Overhead + payload_len;
    if (buf.size() < total_len)
        return 0;

    return openvpn::EncryptDataV2InPlace(
        buf,
        payload_len,
        session_id,
        packet_id,
        current_key_id,
        cipher_iv,
        *encrypt_ctx);
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

    if (logger)
        logger->debug("RxDecryptState::ApplySnapshot: installing key_id={} decrypt_key_fp={}",
                      snap.key_id,
                      openvpn::KeyMaterialFingerprint(snap.decrypt_key.cipher_key));
    // Install new primary decrypt key
    primary = openvpn::DecryptKeySlot{};
    primary.key = snap.decrypt_key;
    primary.replay.Reset();

    // Create persistent AEAD decrypt context
    if (openvpn::IsSupportedAead(snap.decrypt_key.cipher_algorithm))
    {
        const auto *traits = openvpn::GetAeadTraits(snap.decrypt_key.cipher_algorithm);
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
    return openvpn::DecryptDataV2InPlace({&primary, lame_duck ? &*lame_duck : nullptr},
                                         buf,
                                         {.logger = logger,
                                          .no_key_limiter = &no_key_limiter,
                                          .too_old_limiter = &too_old_limiter,
                                          .auth_fail_limiter = &auth_fail_limiter,
                                          .replayed_packets = &replayed_packets,
                                          .log_prefix = "RxDecryptState",
                                          .warn_on_duplicate_replay = false,
                                          .log_packet_too_small = false,
                                          .log_not_data_packet = false,
                                          .log_unsupported_cipher = false});
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
