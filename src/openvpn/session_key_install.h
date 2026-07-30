// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_SESSION_KEY_INSTALL_H
#define CLV_VPN_OPENVPN_SESSION_KEY_INSTALL_H

/**
 * @file session_key_install.h
 * @brief Shared KeyDerivation::InstallKeys wrappers for server sessions and client channels.
 */

#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/key_derivation.h"

#include <span>
#include <spdlog/logger.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace clv::vpn::openvpn {

/**
 * @brief Install derived keys on a server session's CryptoContext.
 * @param session Target connection (null returns false)
 * @param key_material Key-method-2 material
 * @param cipher_algo Negotiated cipher
 * @param hmac_algo Negotiated HMAC (unused for AEAD)
 * @param key_id OpenVPN key slot identifier
 * @param logger Logger for success/failure
 * @return true if keys were installed
 */
inline bool InstallSessionKeys(Connection *session,
                               const std::vector<std::uint8_t> &key_material,
                               CipherAlgorithm cipher_algo,
                               HmacAlgorithm hmac_algo,
                               std::uint8_t key_id,
                               spdlog::logger &logger)
{
    if (!session)
        return false;

    const bool keys_installed = KeyDerivation::InstallKeys(session->GetCryptoContext(),
                                                           key_material,
                                                           cipher_algo,
                                                           hmac_algo,
                                                           key_id);

    if (keys_installed)
    {
        logger.info("Data channel session keys installed successfully (key_id={})", key_id);
        session->GetCryptoContext().SetCurrentKeyId(key_id);
    }
    else
    {
        logger.error("Failed to install data channel session keys");
    }

    return keys_installed;
}

/**
 * @brief Install client-role keys or throw on failure.
 * @param crypto_context Client CryptoContext to receive keys
 * @param key_material Key-method-2 material
 * @param cipher_algo Negotiated cipher
 * @param hmac_algo Negotiated HMAC (unused for AEAD)
 * @param key_id OpenVPN key slot identifier
 * @param transport_label Prefix for the thrown error message (e.g. "UDP")
 * @throws std::runtime_error if InstallKeys fails
 */
inline void InstallClientCryptoKeysOrThrow(CryptoContext &crypto_context,
                                           std::span<const std::uint8_t> key_material,
                                           CipherAlgorithm cipher_algo,
                                           HmacAlgorithm hmac_algo,
                                           std::uint8_t key_id,
                                           std::string_view transport_label)
{
    if (!KeyDerivation::InstallKeys(crypto_context,
                                    key_material,
                                    cipher_algo,
                                    hmac_algo,
                                    key_id,
                                    PeerRole::Client))
    {
        throw std::runtime_error(std::string(transport_label) + ": KeyDerivation::InstallKeys failed");
    }
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_SESSION_KEY_INSTALL_H
