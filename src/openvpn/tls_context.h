// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_TLS_CONTEXT_H
#define CLV_VPN_OPENVPN_TLS_CONTEXT_H

#include "HelpSslContext.h"
#include "HelpSslHandshakeContext.h"

#include <not_null.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn::openvpn {

/**
 * @brief TLS certificate configuration for both server and client modes
 * @details Each field can be either a filesystem path or inline PEM content.
 * If the ca_cert_pem / local_cert_pem / local_key_pem strings are non-empty
 * they take priority over the file-path equivalents.
 */
struct TlsCertConfig
{
    std::string ca_cert;    ///< Path to CA certificate file (for peer verification)
    std::string local_cert; ///< Path to local certificate file (server or client)
    std::string local_key;  ///< Path to local private key file

    // Inline PEM alternatives (take priority when non-empty)
    std::string ca_cert_pem;    ///< CA certificate PEM content
    std::string local_cert_pem; ///< Local certificate PEM content
    std::string local_key_pem;  ///< Local private key PEM content
};

/**
 * @brief Memory BIO-based TLS context for OpenVPN control channel
 *
 * Manages TLS handshake using in-memory BIOs instead of socket I/O.
 * This allows manual control over data flow (needed for OpenVPN's packet model).
 *
 * Usage:
 *   TlsContext tls(true, cert_config);  // server with certs
 *   auto packet = tls.ProcessIncomingData(client_data);
 *   if (packet) { send(*packet); }
 */
class TlsContext
{
  public:
    explicit TlsContext(bool is_server, std::optional<TlsCertConfig> cert_config, spdlog::logger &logger);
    ~TlsContext() = default;

    // Non-copyable, movable
    TlsContext(const TlsContext &) = delete;
    TlsContext &operator=(const TlsContext &) = delete;
    TlsContext(TlsContext &&) = default;
    TlsContext &operator=(TlsContext &&) = default;

    /**
     * @brief Feed incoming TLS data to the handshake state machine
     * @param data Received TLS record/handshake data
     * @return Optional data to send back to peer (may be empty)
     *         Returns nullopt on fatal error
     */
    std::optional<std::vector<std::uint8_t>> ProcessIncomingData(std::span<const std::uint8_t> data);

    /**
     * @brief Check if TLS handshake is complete
     */
    bool IsHandshakeComplete() const
    {
        return handshake_ && handshake_->IsComplete();
    }

    /**
     * @brief Get the negotiated master secret (after handshake)
     * @return Master secret for key derivation, or nullopt if not yet ready
     */
    std::optional<std::vector<std::uint8_t>> GetMasterSecret() const;

    /**
     * @brief Get the handshake context
     * @return Pointer to handshake context, or nullptr if not initialized
     *
     * Use this to access the TLS exporter functionality.
     */
    const clv::OpenSSL::SslHandshakeContext *GetHandshake() const
    {
        return handshake_ ? &(*handshake_) : nullptr;
    }

    /**
     * @brief Get the negotiated cipher suite name
     * @return Cipher name (e.g., "TLS_AES_256_GCM_SHA384"), or empty if not negotiated
     */
    std::string GetCipherName() const
    {
        return handshake_ ? handshake_->GetCipherName() : "";
    }

    /**
     * @brief Get pending data to transmit (call after ProcessIncomingData)
     * @return Queued outbound data, or empty vector if nothing pending
     */
    std::vector<std::uint8_t> GetPendingData();

    /**
     * @brief Write application data to TLS tunnel (encrypt)
     * @param data Plaintext data to send through TLS
     * @return Number of bytes written, or -1 on error
     *
     * Use GetPendingData() after to get encrypted TLS records.
     */
    int WriteAppData(std::span<const std::uint8_t> data);

    /**
     * @brief Read decrypted application data from TLS tunnel
     * @return Decrypted plaintext, or empty vector if no data
     *
     * Call after feeding encrypted data via FeedEncryptedData().
     */
    std::vector<std::uint8_t> ReadAppData();

    /**
     * @brief Feed encrypted TLS data after handshake (for decryption)
     * @param data Encrypted TLS records from peer
     * @return true if successfully fed to TLS engine
     */
    bool FeedEncryptedData(std::span<const std::uint8_t> data);

  private:
    clv::OpenSSL::SslContext ssl_ctx_{nullptr};                  // SSL_CTX object
    std::optional<clv::OpenSSL::SslHandshakeContext> handshake_; // Handshake state machine
    clv::not_null<spdlog::logger *> logger_;                     // Logger for debug output (never null)
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_TLS_CONTEXT_H
