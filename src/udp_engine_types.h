// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_ENGINE_TYPES_H
#define CLV_VPN_UDP_ENGINE_TYPES_H

#include "HelpSslCipher.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "routing_table.h"
#include "transport/transport.h"

#include <rate_limiter.h>

#include <cstddef>
#include <optional>
#include <qsbr_type.h>

#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

namespace clv::vpn {

// Forward declarations
class Connection;
class SessionManager;

// ============================================================================
// SessionIndex — lightweight copyable session lookup for TX thread
// ============================================================================

/**
 * @brief Per-session snapshot of state that TX and RX threads need.
 *
 * Published by the control plane inside QsbrType<SessionIndex>.
 * TX/RX read via read_quiesced() — zero synchronization cost.
 */
struct SessionEntry
{
    Connection *conn = nullptr;           ///< Transport handle (valid until QSBR reclaims)
    openvpn::EncryptionKey encrypt_key{}; ///< Encrypt-side key material
    openvpn::EncryptionKey decrypt_key{}; ///< Decrypt-side key material (for RX thread)
    std::uint8_t key_id = 0;              ///< P_DATA_V2 key_id for outbound packets
    transport::PeerEndpoint endpoint{};   ///< Remote peer endpoint (for RX endpoint lookup)
};

/**
 * @brief Copyable flat map of session_id → SessionEntry.
 *
 * Owned by QsbrType<SessionIndex>.  Control plane publishes a new snapshot
 * whenever sessions are added/removed or keys rotate.  TX reads the current
 * snapshot via read_quiesced().  Only sessions with valid encrypt keys and
 * an active transport are included — TX can assume every entry is ready for
 * encryption.
 */
struct SessionIndex
{
    std::unordered_map<std::uint64_t, SessionEntry> entries;

    /// Reverse index: endpoint → session_id for RX thread lookup.
    std::unordered_map<transport::PeerEndpoint, std::uint64_t> by_endpoint;

    /// Look up a session entry by SessionId.  Returns nullptr if not found.
    const SessionEntry *Find(openvpn::SessionId id) const;

    /// Look up a session entry by peer endpoint.  Returns nullptr if not found.
    const SessionEntry *FindByEndpoint(const transport::PeerEndpoint &ep) const;

    /// Number of sessions in the index.
    std::size_t size() const
    {
        return entries.size();
    }

    /// Build a SessionIndex from the current SessionManager state.
    /// Only includes sessions with valid encrypt keys and active transport.
    static SessionIndex BuildFrom(const SessionManager &sm);
};

// ============================================================================
// TxEncryptState — per-session TX-owned mutable encrypt state
// ============================================================================

/**
 * @brief Per-connection encrypt state owned exclusively by the TX thread.
 *
 * TX maintains one TxEncryptState per active session.  The AEAD cipher
 * context and packet-ID counter live here — never shared, never locked.
 * When the control plane rotates keys (detected via key_id change in the
 * SessionEntry snapshot), TX reinitializes the context from the new key
 * material.
 */
struct TxEncryptState
{
    std::uint32_t outbound_packet_id = 1;                  ///< Monotonic packet ID counter
    std::optional<clv::OpenSSL::SslCipherCtx> encrypt_ctx; ///< Persistent AEAD context
    std::uint8_t current_key_id = 0;                       ///< Last-applied key_id
    std::vector<std::uint8_t> cipher_iv;                   ///< Cached IV salt for nonce generation
    bool valid = false;                                    ///< True after first ApplySnapshot

    /// Returns true if the published key_id differs from our cached one.
    bool NeedsReinit(std::uint8_t published_key_id) const;

    /// Reinitialize encrypt context from new key material.
    /// Resets the persistent AEAD context with the new key schedule.
    /// Does NOT reset outbound_packet_id (it's monotonic across rekeys).
    void ApplySnapshot(const openvpn::EncryptionKey &key, std::uint8_t key_id);

    /**
     * @brief Encrypt a TUN packet in-place using TX-local state.
     *
     * Identical wire format to DataChannel::EncryptPacketInPlace, but reads
     * key material and cipher context from this TxEncryptState rather than
     * from the shared DataChannel.
     *
     * @param buf   Buffer with at least (kDataV2Overhead + payload_len) bytes.
     *              Plaintext must already be at offset kDataV2Overhead.
     * @param payload_len  Length of plaintext at buf[kDataV2Overhead..]
     * @param session_id   Session ID for P_DATA_V2 peer_id field
     * @return Total wire packet length (kDataV2Overhead + payload_len), or 0 on error.
     */
    [[nodiscard]] std::size_t EncryptInPlace(std::span<std::uint8_t> buf,
                                             std::size_t payload_len,
                                             openvpn::SessionId session_id);

    /**
     * @brief Encrypt with a pre-assigned packet ID (partition pre-assign path).
     *
     * Same as the 3-param overload but uses the caller-supplied packet_id
     * instead of incrementing the internal counter.  Used by the partition
     * encrypt path where the reader thread pre-stamps packet IDs during fill.
     */
    [[nodiscard]] std::size_t EncryptInPlace(std::span<std::uint8_t> buf,
                                             std::size_t payload_len,
                                             openvpn::SessionId session_id,
                                             std::uint32_t packet_id);
};

// ============================================================================
// DeferredConnection — QSBR-safe deferred destruction
// ============================================================================

/**
 * @brief Entry in the deferred-destruction queue.
 *
 * When the control plane removes a session, the Connection cannot be freed
 * immediately because the TX thread may still hold a pointer from the
 * previous SessionIndex snapshot.  Instead the Connection is moved here
 * with the current QSBR epoch.  After TX passes a quiescent checkpoint
 * for that epoch, the Connection is safely destroyed.
 */
struct DeferredConnection
{
    std::unique_ptr<Connection> conn;
    std::uint64_t epoch = 0;

    DeferredConnection() = default;
    DeferredConnection(std::unique_ptr<Connection> c, std::uint64_t e);
    ~DeferredConnection();
    DeferredConnection(DeferredConnection &&) noexcept;
    DeferredConnection &operator=(DeferredConnection &&) noexcept;
};

// ============================================================================
// UdpEngineContext — QSBR-protected shared state bundle
// ============================================================================

/**
 * @brief Bundle of all QSBR-protected shared state for split-datapath mode.
 *
 * Owned by VpnServer / VpnClient.  The control plane (RX + control thread)
 * mutates the canonical SessionManager / RoutingTable and then publishes
 * new snapshots here.  The TX thread reads via read_quiesced() with zero
 * synchronization overhead and reports quiescent state between batches.
 *
 * All QsbrType instances share a single QsbrCore so that one
 * quiescent_state() call advances epochs for all of them.
 */
struct UdpEngineContext
{
    std::shared_ptr<QsbrCore> core;

    QsbrType<RoutingTableIpv4> routes_v4;
    QsbrType<RoutingTableIpv6> routes_v6;
    QsbrType<SessionIndex> sessions;    ///< TX snapshot — activated on ACK
    QsbrType<SessionIndex> sessions_rx; ///< RX snapshot — activated immediately at key derivation

    /// Deferred destruction queue.  Control plane appends; reclaimed
    /// periodically after TX passes the required epoch.
    std::vector<DeferredConnection> deferred;

    /// Whether the control-plane thread has been registered with QSBR.
    bool cp_registered_ = false;

    /// Construct with empty routing tables and session index.
    UdpEngineContext();
    ~UdpEngineContext();

    /// Non-copyable, non-movable (contains QsbrType members).
    UdpEngineContext(const UdpEngineContext &) = delete;
    UdpEngineContext &operator=(const UdpEngineContext &) = delete;
    UdpEngineContext(UdpEngineContext &&) = delete;
    UdpEngineContext &operator=(UdpEngineContext &&) = delete;

    /// Publish updated routing tables (call after any route mutation).
    void PublishRoutes(const RoutingTableIpv4 &v4, const RoutingTableIpv6 &v6);

    /// Publish updated session index (call after session add/remove or key install).
    void PublishSessions(const SessionIndex &idx);

    /// Convenience: rebuild and publish session index from SessionManager.
    void PublishSessions(const SessionManager &sm);

    /// Publish updated RX-only decrypt snapshot (call immediately after key derivation,
    /// before KEY_METHOD_2 is sent).  TX snapshot (sessions) is NOT updated here.
    void PublishSessionsRx(const SessionManager &sm);

    /// Defer destruction of a removed Connection until TX passes quiescent.
    void DeferDestruction(std::unique_ptr<Connection> conn);

    /// Reclaim deferred connections whose epoch has been passed by all readers.
    /// Lazily registers the calling (control-plane) thread with QSBR on first
    /// call, because qsbr_sync requires the caller to be registered.
    void ReclaimDeferred();

    /// Force-free all retired QSBR pointers and unregister this thread.
    /// Must be called from the same thread that performed write() / ReclaimDeferred()
    /// (i.e. the control-plane IO thread), after all data-path readers have stopped.
    /// This must be called before the UdpEngineContext is destroyed from a different
    /// thread, otherwise the thread-local retired lists will be unreachable.
    void ForceReclaimAll();
};

// ============================================================================
// ClientTxSnapshot — lightweight TX-thread state for client split-datapath
// ============================================================================

/**
 * @brief Snapshot of all state the client TX thread needs.
 *
 * Published by the control plane via asio::post() to the TX io_context.
 * Because the TX thread's io_context serializes execution, no atomics or
 * locks are needed — the posted update runs between batch iterations.
 */
struct ClientTxSnapshot
{
    int socket_fd = -1;              ///< UDP socket native handle
    transport::PeerEndpoint peer{};  ///< Server endpoint for sendmmsg
    openvpn::SessionId session_id{}; ///< Server-assigned peer ID (P_DATA_V2)
    std::uint8_t key_id = 0;         ///< P_DATA_V2 key_id for outbound (kept in sync with key_slots_)
    bool valid = false;              ///< True once the session is ready for data
};

// ============================================================================
// RxDecryptSnapshot — published from control plane to RX thread
// ============================================================================

/**
 * @brief Snapshot of decrypt key material for the RX thread.
 *
 * Published by the control plane via asio::post() to the RX io_context
 * after key derivation.  The RX thread uses this to initialize its own
 * persistent AEAD decrypt context and replay window.
 */
struct RxDecryptSnapshot
{
    openvpn::EncryptionKey decrypt_key{}; ///< Decrypt-side key material
    std::uint8_t key_id = 0;              ///< Key ID for matching incoming packets
    bool valid = false;                   ///< True once keys are ready
};

// ============================================================================
// RxDecryptState — per-connection RX-owned mutable decrypt state
// ============================================================================

/**
 * @brief RX-thread-local decrypt state for the client split-datapath.
 *
 * Mirrors the decrypt side of DataChannel, but owned exclusively by the
 * RX thread.  The persistent AEAD context, replay window, and key slots
 * live here — never shared, never locked.  When the control plane rotates
 * keys (detected via key_id change in the snapshot), the RX thread
 * reinitializes the context from the new key material.
 */
struct RxDecryptState
{
    // Default constructor — used when map operator[] inserts a new entry.
    // Caller must set logger before the first packet is decrypted.
    RxDecryptState() = default;

    /// Construct with a logger — use this in Policy constructors and Reset().
    explicit RxDecryptState(spdlog::logger &log) noexcept : logger(&log)
    {
    }

    openvpn::DecryptKeySlot primary;                               ///< Primary decrypt key + replay + AEAD ctx
    std::optional<openvpn::DecryptKeySlot> lame_duck;              ///< Old key during transition
    std::uint64_t replayed_packets = 0;                            ///< Replay counter
    clv::RateLimiter<> no_key_limiter;                             ///< Throttle "no key" warnings
    clv::RateLimiter<> too_old_limiter;                            ///< Throttle "too old" warnings
    clv::RateLimiter<> auth_fail_limiter{std::chrono::seconds{5}}; ///< Throttle auth failure errors
    spdlog::logger *logger = nullptr;                              ///< Logger (non-owning; always set before use)
    std::uint8_t current_key_id = 255;                             ///< Sentinel: no key installed
    bool valid = false;                                            ///< True after first ApplySnapshot

    /// Returns true if the published key_id differs from our cached one.
    bool NeedsReinit(std::uint8_t published_key_id) const;

    /// Reinitialize decrypt context from new key material.
    /// Moves current primary to lame duck and installs new key as primary.
    void ApplySnapshot(const RxDecryptSnapshot &snap);

    /**
     * @brief Decrypt a data-channel packet in-place using RX-local state.
     *
     * Identical wire format to DataChannel::DecryptPacketInPlace, but reads
     * key material and cipher context from this RxDecryptState rather than
     * from the shared DataChannel.
     *
     * @param buf Wire packet (P_DATA_V2 header + packet_id + tag + ciphertext)
     * @return Plaintext span within buf, or empty on error/replay.
     */
    [[nodiscard]] std::span<std::uint8_t> DecryptPacketInPlace(std::span<std::uint8_t> buf);
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_ENGINE_TYPES_H
