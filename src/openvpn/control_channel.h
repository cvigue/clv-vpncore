// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CONTROL_CHANNEL_H
#define CLV_VPN_OPENVPN_CONTROL_CHANNEL_H

#include "packet.h"
#include "tls_context.h"

#include <not_null.h>

#include <algorithm>
#include <asio.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn::openvpn {

/**
 * @brief ACK/Retransmit tracking for control packets we have sent
 * @note We also track ACKs we need to send back to the peer elsewhere in the ControlChannel class
 *
 * OpenVPN control channel requires reliable delivery. This implements:
 * - Per-packet sequence tracking
 * - Automatic retransmission on timeout
 * - ACK handling and duplicate detection
 */
struct AckTracker
{
    /// Initial retransmission timeout; backed off exponentially per attempt
    static constexpr auto INITIAL_RTO = std::chrono::milliseconds(500);

    /// Maximum retransmission timeout cap
    static constexpr auto MAX_RTO = std::chrono::milliseconds(8000);

    /// Maximum number of retransmission attempts
    static constexpr int MAX_RETRANSMIT_ATTEMPTS = 64;

    /// Construct a tracker for an outbound packet
    AckTracker(std::uint32_t packet_id, std::span<const std::uint8_t> data)
        : packet_id_(packet_id), packet_data_(data.begin(), data.end()), sent_at_(std::chrono::steady_clock::now())
    {
    }

    /// Default constructor for map operations
    AckTracker() = default;

    /// Packet sequence ID for retransmission tracking
    std::uint32_t packet_id_ = 0;

    /// Serialized packet data to retransmit
    std::vector<std::uint8_t> packet_data_;

    /// Time packet was sent (for timeout calculation)
    std::chrono::steady_clock::time_point sent_at_{};

    /// Number of retransmission attempts so far
    int retransmit_count_ = 0;

    /// Whether this packet has been ACKed
    bool acknowledged_ = false;

    /**
     * @brief Check if this packet should be retransmitted
     * @param now Current time
     * @return true if timeout exceeded and retransmits remaining
     */
    bool ShouldRetransmit(std::chrono::steady_clock::time_point now) const
    {
        if (acknowledged_)
            return false;
        if (retransmit_count_ >= MAX_RETRANSMIT_ATTEMPTS)
            return false;

        auto effective_timeout = CurrentRetransmitTimeout();
        return (now - sent_at_) >= effective_timeout;
    }

    /**
     * @brief Compute the current RTO with exponential backoff and a hard cap
     */
    std::chrono::milliseconds CurrentRetransmitTimeout() const
    {
        // Exponential backoff: initial * 2^retransmit_count (capped)
        auto scaled = INITIAL_RTO * (1 << std::min(retransmit_count_, 6)); // cap growth
        if (scaled > MAX_RTO)
            scaled = MAX_RTO;
        return scaled;
    }
};

/**
 * @brief OpenVPN control channel state machine
 *
 * Implements the TLS-based control channel protocol including:
 * - Handshake negotiation (hard reset, soft reset)
 * - TLS state transitions
 * - Packet sequencing and ACKs
 * - Timeout and retransmission
 *
 * @note Design: This class uses defensive programming with explicit validation
 * and detailed error logging. This is intentional - the control channel handles
 * connection setup and key renegotiation (infrequent operations), not the high-
 * throughput data path. Clarity and debuggability are prioritized over micro-
 * optimization. The data channel (P_DATA_V2) is where hot-path optimization matters.
 *
 * @todo This class is sort of big, and could likely benefit from decomposition.
 */
class ControlChannel
{
  public:
    /// State of the control channel handshake
    enum class State
    {
        Disconnected,     ///< Initial state, not connected
        HardResetPending, ///< Waiting for peer response after initiating hard reset
        TlsHandshake,     ///< TLS handshake in progress
        KeyMaterialReady, ///< TLS handshake complete, key material exchanged
        Active,           ///< Control channel is active and ready to transmit data
        SoftResetPending, ///< Soft reset requested, renegotiating
        Error             ///< Fatal error state
    };

    /**
     * @todo Consider adding a full constructor that takes (logger, is_server, session_id, cert_config)
     * to allow single-step initialization for Connection. The current two-step pattern
     * (construct + Initialize()) is required by VpnClient which defers init until Connect(),
     * but Connection always has all parameters available at construction time.
     */
    explicit ControlChannel(spdlog::logger &logger) : logger_(&logger)
    {
    }
    ~ControlChannel() = default;

    // Non-copyable
    ControlChannel(const ControlChannel &) = delete;
    ControlChannel &operator=(const ControlChannel &) = delete;
    // Moveable
    ControlChannel(ControlChannel &&) = default;
    ControlChannel &operator=(ControlChannel &&) = default;


    /**
     * @brief Initialize control channel with TLS handshake context
     * @param is_server true for server-side, false for client-side
     * @param initial_session_id Session ID for this connection
     * @param cert_config Optional TLS certificate configuration
     * @return true if initialization successful
     */
    bool Initialize(bool is_server, SessionId initial_session_id, std::optional<TlsCertConfig> cert_config);

    /**
     * @brief Reset all state so Initialize() can be called again (e.g. on reconnect).
     *
     * Safe to call in any state.  After this call the object is in the same
     * condition as a freshly-constructed one (logger is preserved).
     */
    void Reset();

    /**
     * @brief Start outbound hard reset (client-initiated handshake)
     * @param key_id TLS key index (0-7)
     * @return Serialized hard reset packet, or empty if failed
     */
    std::vector<std::uint8_t> StartHardReset(std::uint8_t key_id = 0);

    /**
     * @brief Handle incoming hard reset from peer
     * @param packet Parsed OpenVpnPacket
     * @return true if reset handled successfully
     */
    bool HandleHardReset(const OpenVpnPacket &packet);

    /**
     * @brief Handle incoming soft reset (renegotiation) from peer
     * @param packet Parsed OpenVpnPacket containing soft reset
     * @param cert_config TLS certificate configuration for new handshake
     * @return Serialized response packet (soft reset acknowledgment), or empty on error
     */
    std::vector<std::uint8_t> HandleSoftReset(const OpenVpnPacket &packet, const TlsCertConfig &cert_config);

    /**
     * @brief Get the current key ID used for this session
     * @return Key ID (0-7)
     */
    std::uint8_t GetKeyId() const
    {
        return key_id_;
    }

    /**
     * @brief Generate hard reset response packet (server-side)
     * @param client_opcode Opcode from client's hard reset packet
     * @return Serialized hard reset response packet, or empty if failed
     */
    std::vector<std::uint8_t> GenerateHardResetResponse(Opcode client_opcode);

    /**
     * @brief Generate explicit ACK packet for pending acknowledgments
     * @return Serialized P_ACK_V1 packet, or empty if no pending ACKs
     */
    std::vector<std::uint8_t> GenerateExplicitAck();

    /**
     * @brief Initiate TLS handshake (server sends ServerHello)
     * @return Optional TLS data to send, or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> InitiateTlsHandshake();

    /**
     * @brief Request soft reset (renegotiation)
     * @return Serialized soft reset packet, or empty if not in Active state
     */
    std::vector<std::uint8_t> RequestSoftReset();

    /**
     * @brief Process TLS handshake data from peer
     * @param control_packet Parsed control packet containing TLS data
     * @return Optional vector of serialized TLS response packets (may be fragmented)
     */
    std::optional<std::vector<std::vector<std::uint8_t>>> ProcessTlsData(const OpenVpnPacket &control_packet);

    /**
     * @brief Prepare TLS-encrypted application data for transmission
     * @param plaintext Plaintext to encrypt through TLS tunnel
     * @return Vector of serialized control packets containing encrypted TLS records,
     *         or empty vector on error
     *
     * Use this for post-handshake messages like PUSH_REPLY that must go through TLS.
     */
    std::vector<std::vector<std::uint8_t>> PrepareTlsEncryptedData(std::span<const std::uint8_t> plaintext);

    /**
     * @brief Handle ACK packet from peer
     * @param packet Parsed ACK packet
     * @return true if ACK processed successfully
     */
    bool HandleAck(const OpenVpnPacket &packet);

    /**
     * @brief Get queued packets that fit within send window
     * @return Vector of serialized packets ready to send
     */
    std::vector<std::vector<std::uint8_t>> GetPacketsToSend();

    /**
     * @brief Process retransmissions for unacknowledged packets
     * @param now Current time
     * @return Vector of packets to retransmit
     */
    std::vector<std::vector<std::uint8_t>> ProcessRetransmissions(
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    /**
     * @brief Get current state of control channel
     */
    State GetState() const
    {
        return state_;
    }

    /**
     * @brief Check if control channel is ready to transmit data
     */
    bool IsActive() const
    {
        return state_ == State::Active;
    }

    /**
     * @brief Get the session ID for this connection
     */
    SessionId GetSessionId() const
    {
        return session_id_;
    }

    /**
     * @brief Get the peer's session ID (remote side)
     */
    std::optional<SessionId> GetPeerSessionId() const
    {
        return peer_session_id_;
    }

    /**
     * @brief Get next outbound packet ID (for sequencing)
     */
    std::uint32_t GetNextPacketId()
    {
        return outbound_packet_id_++;
    }

    /**
     * @brief Set expected inbound packet ID for validation
     * @param packet_id Last received packet ID
     */
    void SetLastReceivedPacketId(std::uint32_t packet_id)
    {
        last_received_packet_id_ = packet_id;
    }

    /**
     * @brief Read decrypted plaintext received after TLS handshake
     * @return Decrypted plaintext data, or empty if none available
     *
     * This returns data received through the TLS tunnel after handshake completes,
     * such as the peer's key-method 2 message.
     */
    std::vector<std::uint8_t> ReadPlaintext();

    /**
     * @brief Check if there is decrypted plaintext available to read
     */
    bool HasPlaintext() const
    {
        return !received_plaintext_.empty();
    }

    /**
     * @brief Get count of pending ACKs (for testing)
     */
    size_t GetPendingAckCount() const
    {
        return pending_acks_.size();
    }

    /**
     * @brief Get last received packet ID (for testing)
     */
    std::uint32_t GetLastReceivedPacketId() const
    {
        return last_received_packet_id_;
    }

    /**
     * @brief Get the TLS handshake context
     * @return Pointer to TLS context, or nullptr if not initialized
     *
     * Use this to access TLS exporter functionality for key derivation.
     */
    const openvpn::TlsContext *GetTlsContext() const
    {
        return tls_context_ ? &(*tls_context_) : nullptr;
    }

    /**
     * @brief Get the negotiated cipher suite name
     * @return Cipher name, or empty if TLS handshake not complete
     */
    std::string GetCipherName() const
    {
        return tls_context_ ? tls_context_->GetCipherName() : "";
    }

  private:
    /// Current handshake state
    State state_ = State::Disconnected;

    /// Session ID for this connection (our own session ID)
    SessionId session_id_{};

    /// Peer's session ID (received from remote)
    std::optional<SessionId> peer_session_id_;

    /// TLS context for handshake
    std::optional<TlsContext> tls_context_;

    /// Current TLS key index (0-7)
    std::uint8_t key_id_ = 0;

    /// Outbound packet sequencing (starts at 0 per OpenVPN protocol)
    std::uint32_t outbound_packet_id_ = 0;

    /// Last received packet ID (for anti-replay), UINT32_MAX means none received yet
    std::uint32_t last_received_packet_id_ = UINT32_MAX;

    /// Pending outbound ACKs (packet IDs to acknowledge)
    std::deque<std::uint32_t> pending_acks_;

    /**
     * ACKs currently in flight, keyed by our packet_id that carried them
     * When our packet is ACKed, we remove its entry. If retransmitted, we move
     * those ACKs to reack_candidates_ for one re-ack attempt.
     */
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> in_flight_acks_;

    /**
     * ACKs whose carrier packet timed out - candidates for one re-ack attempt
     * If their carrier also times out, we drop them (peer probably got them)
     */
    std::deque<std::uint32_t> reack_candidates_;

    /// Tracking for unacknowledged outbound packets
    std::unordered_map<std::uint32_t, AckTracker> unacked_packets_;

    /// TLS handshake buffer (accumulates TLS records)
    std::vector<std::uint8_t> tls_buffer_;

    /// Whether we initiated the connection (client) vs received it (server)
    bool is_client_ = false;

    /// Queue of pending fragments to send (for send window control)
    std::deque<std::vector<std::uint8_t>> pending_fragments_;

    /// Buffer for received decrypted plaintext (post-handshake app data)
    std::vector<std::uint8_t> received_plaintext_;

    /// Maximum number of unacknowledged packets allowed (send window size)
    static constexpr size_t MAX_SEND_WINDOW = 4;

    /// Structured logger (never null)
    clv::not_null<spdlog::logger *> logger_;

    /// Helper: Send a hard reset packet
    std::vector<std::uint8_t> SendHardReset(std::uint8_t key_id, bool is_client);

    /// Helper: Mark packet as pending ACK
    void TrackOutboundPacket(std::uint32_t packet_id, std::span<const std::uint8_t> data);

    /// Helper: Check anti-replay (ensure packet_id > last_received_packet_id)
    bool ValidatePacketId(std::uint32_t packet_id);

    /// Helper: Count unacknowledged packets
    size_t CountUnacknowledgedPackets() const;

    /**
     * Helper: Collect up to MAX_ACK_COUNT ACKs for piggybacking
     * Pulls from reack_candidates_ first (one re-ack attempt), then pending_acks_.
     * Returns the collected ACKs and removes them from their source deques.
     */
    std::vector<std::uint32_t> CollectAcksForPiggyback();

    /// Helper: Record which ACKs were sent on a given packet_id
    void RecordInFlightAcks(std::uint32_t packet_id, std::span<const std::uint32_t> acks);

    /// Helper: Called when our packet is acknowledged - removes from in_flight_acks_
    void ClearInFlightAcks(std::uint32_t packet_id);

    /// Helper: Called when our packet times out - moves ACKs to reack_candidates_
    void RescueInFlightAcks(std::uint32_t packet_id);

    /**
     * Helper: Process TLS handshake data (ClientHello, Certificate, etc.)
     * @param payload TLS handshake records from peer
     * @return Response packets to send, or nullopt on fatal error
     */
    std::optional<std::vector<std::vector<std::uint8_t>>> ProcessTlsHandshakeData(
        std::span<const std::uint8_t> payload);

    /**
     * Helper: Process application data after TLS handshake is complete
     * @param payload Encrypted TLS application data from peer
     * @return Empty vector on success (data stored in received_plaintext_), nullopt on error
     */
    std::optional<std::vector<std::vector<std::uint8_t>>> ProcessPostHandshakeAppData(
        std::span<const std::uint8_t> payload);

    /**
     * Helper: Fragment TLS response data into MTU-sized control packets
     * @param tls_data Raw TLS records to fragment
     * @return Vector of serialized control packets, first one to send immediately,
     *         rest queued in pending_fragments_
     */
    std::vector<std::vector<std::uint8_t>> FragmentTlsResponse(
        std::span<const std::uint8_t> tls_data);

    /**
     * Helper: Create a control packet with optional ACK piggybacking
     * @param payload TLS data payload
     * @param packet_id Packet sequence ID
     * @return Serialized control packet
     */
    std::vector<std::uint8_t> CreateControlPacketWithAcks(
        std::vector<std::uint8_t> payload, std::uint32_t packet_id);
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_CONTROL_CHANNEL_H
