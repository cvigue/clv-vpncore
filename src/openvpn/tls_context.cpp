// Copyright (c) 2025- Charlie Vigue. All rights reserved.
#include "tls_context.h"
#include <log_utils.h>
#include "HelpSslException.h"
#include "HelpSslHandshakeContext.h"

#include <array>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

#include <spdlog/spdlog.h>

#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <sys/types.h>
#include <type_traits>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace clv::vpn::openvpn {
TlsContext::TlsContext(bool is_server, std::optional<TlsCertConfig> cert_config, spdlog::logger &logger)
    : ssl_ctx_(is_server ? TLS_server_method() : TLS_client_method()), logger_(&logger)
{
    // Configure TLS version: use TLS 1.2 only for compatibility
    // OpenSSL 3.0.13 has issues with some TLS 1.3 extensions from newer clients
    ssl_ctx_.SetMinProtoVersion(TLS1_2_VERSION);
    ssl_ctx_.SetMaxProtoVersion(TLS1_2_VERSION);

    // Use permissive cipher list for OpenVPN compatibility
    const char *cipher_list = "HIGH:!aNULL:!MD5:!RC4";
    if (!ssl_ctx_.SetCipherListNoEx(cipher_list))
    {
        logger_->warn("Failed to set cipher list");
    }

    ssl_ctx_.SetOptions(SSL_OP_ALL | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    constexpr size_t TLS_MAX_FRAGMENT = 1200; // Leave room for TLS record header (5 bytes)
    ssl_ctx_.SetMaxSendFragment(TLS_MAX_FRAGMENT);

    // Load certificates if provided
    if (cert_config)
    {
        try
        {
            // Load CA certificate for verification (inline PEM preferred)
            if (!cert_config->ca_cert_pem.empty())
            {
                ssl_ctx_.LoadVerifyPem(cert_config->ca_cert_pem);
                if (is_server)
                    ssl_ctx_.SetVerifyMode(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                else
                    ssl_ctx_.SetVerifyMode(SSL_VERIFY_PEER);
            }
            else if (!cert_config->ca_cert.empty())
            {
                ssl_ctx_.LoadVerifyFile(std::filesystem::path(cert_config->ca_cert));
                if (is_server)
                    ssl_ctx_.SetVerifyMode(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                else
                    ssl_ctx_.SetVerifyMode(SSL_VERIFY_PEER); // Client verifies server
            }

            // Load local certificate and private key (inline PEM preferred)
            if (!cert_config->local_cert_pem.empty())
            {
                ssl_ctx_.UseCertificatePem(cert_config->local_cert_pem);
            }
            else if (!cert_config->local_cert.empty())
            {
                ssl_ctx_.UseCertificateChainFile(std::filesystem::path(cert_config->local_cert));
            }
            if (!cert_config->local_key_pem.empty())
            {
                ssl_ctx_.UsePrivateKeyPem(cert_config->local_key_pem);
            }
            else if (!cert_config->local_key.empty())
            {
                ssl_ctx_.UsePrivateKeyFile(std::filesystem::path(cert_config->local_key));
            }
        }
        catch (const clv::OpenSSL::SslException &e)
        {
            logger_->error("Failed to load TLS certificates: {}", e.what());
            throw;
        }
    }

    // Initialize handshake context (delegates all BIO management)
    handshake_.emplace(ssl_ctx_, is_server);
}

std::optional<std::vector<std::uint8_t>>
TlsContext::ProcessIncomingData(std::span<const std::uint8_t> data)
{
    logger_->trace("TlsContext::ProcessIncomingData: input size={}", data.size());
    if (!handshake_ || handshake_->IsComplete())
    {
        logger_->trace("TlsContext::ProcessIncomingData: handshake null or complete");
        return std::vector<std::uint8_t>();
    }

    constexpr std::array<std::string_view, 4> trace_msg = {"wants more data",
                                                           "has data to send",
                                                           "handshake COMPLETE",
                                                           "FAILED"};

    try
    {
        // Process handshake and check result
        auto result = handshake_->ProcessIncomingData(data);

        logger_->trace("TlsContext::ProcessIncomingData: {} [{}]",
                       trace_msg[std::underlying_type_t<decltype(result)>(result)],
                       std::underlying_type_t<decltype(result)>(result));

        // All non-fatal states: return any pending TLS output data
        return handshake_->GetPendingOutput();
    }
    catch (const clv::OpenSSL::SslException &e)
    {
        logger_->error("TLS handshake failed: {}", e.what());
        return std::nullopt;
    }
}

std::optional<std::vector<std::uint8_t>> TlsContext::GetMasterSecret() const
{
    if (!handshake_ || !handshake_->IsComplete())
        return std::nullopt;

    std::vector<uint8_t> empty_context;
    auto key_material = handshake_->ExportKeyMaterial("OPENVPN", empty_context, 32);
    if (!key_material)
        return std::nullopt;

    return key_material;
}

std::vector<std::uint8_t> TlsContext::GetPendingData()
{
    if (!handshake_)
        return {};
    // Get pending output data from the BIO (encrypted TLS records)
    return handshake_->GetPendingOutput();
}

int TlsContext::WriteAppData(std::span<const std::uint8_t> data)
{
    if (!handshake_ || !handshake_->IsComplete())
    {
        logger_->warn("TlsContext::WriteAppData: handshake not complete");
        return -1;
    }
    int written = handshake_->WriteAppData(data);
    logger_->trace("TlsContext::WriteAppData: wrote {} bytes of plaintext", written);
    return written;
}

std::vector<std::uint8_t> TlsContext::ReadAppData()
{
    if (!handshake_ || !handshake_->IsComplete())
        return {};
    auto data = handshake_->ReadAppData();
    if (logger_ && !data.empty())
    {
        logger_->trace("TlsContext::ReadAppData: read {} bytes of plaintext", data.size());
    }
    return data;
}

bool TlsContext::FeedEncryptedData(std::span<const std::uint8_t> data)
{
    if (!handshake_ || !handshake_->IsComplete())
        return false;
    bool ok = handshake_->FeedEncryptedData(data);
    logger_->trace("TlsContext::FeedEncryptedData: fed {} bytes, ok={}", data.size(), ok);
    return ok;
}

} // namespace clv::vpn::openvpn
