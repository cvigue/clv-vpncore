// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "key_derivation.h"
#include "protocol_constants.h"
#include "crypto_algorithms.h"
#include "data_channel.h"
#include <log_utils.h>
#include "HelpSslException.h"
#include "HelpSslEvpPkeyCtx.h"
#include "HelpSslHmac.h"
#include "openvpn/packet.h"
#include <openssl/types.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

std::vector<std::uint8_t>
KeyDerivation::DeriveKeyMaterial(std::span<const std::uint8_t> master_secret,
                                 const std::string &label,
                                 size_t output_bytes)
{
    if (master_secret.empty())
        throw std::runtime_error("Master secret cannot be empty");

    if (output_bytes == 0)
        throw std::runtime_error("Output size must be > 0");

    std::vector<std::uint8_t> result;
    result.reserve(output_bytes);

    // Generate output in 32-byte chunks (HMAC-SHA256 output size)
    std::uint8_t counter = 0;
    while (result.size() < output_bytes)
    {
        auto chunk = PrfIteration(master_secret, label, counter);

        // Copy only what we need to reach output_bytes
        size_t remaining = output_bytes - result.size();
        size_t to_copy = std::min(chunk.size(), remaining);

        result.insert(result.end(),
                      chunk.begin(),
                      chunk.begin() + to_copy);

        counter++;
    }

    return result;
}

std::vector<std::uint8_t> KeyDerivation::PrfIteration(std::span<const std::uint8_t> key,
                                                      const std::string &label,
                                                      std::uint8_t counter)
{
    // Build data: label || 0x00 || counter
    std::vector<std::uint8_t> data;
    data.insert(data.end(), label.begin(), label.end());
    data.push_back(0x00);
    data.push_back(counter);

    // Compute HMAC-SHA256 using SslHelp wrapper
    try
    {
        auto hmac_result = clv::OpenSSL::HmacSha256(key, data);
        return std::vector<std::uint8_t>(hmac_result.begin(), hmac_result.end());
    }
    catch (const clv::OpenSSL::SslException &e)
    {
        throw std::runtime_error(std::string("HMAC-SHA256 computation failed: ") + e.what());
    }
}

// OpenVPN key structure constants (from crypto.h)
// struct key { uint8_t cipher[MAX_CIPHER_KEY_LENGTH]; uint8_t hmac[MAX_HMAC_KEY_LENGTH]; }
// where MAX_CIPHER_KEY_LENGTH = 64, MAX_HMAC_KEY_LENGTH = 64
constexpr size_t OPENVPN_MAX_CIPHER_KEY_LENGTH = 64;
constexpr size_t OPENVPN_MAX_HMAC_KEY_LENGTH = 64;
constexpr size_t OPENVPN_KEY_SIZE = OPENVPN_MAX_CIPHER_KEY_LENGTH + OPENVPN_MAX_HMAC_KEY_LENGTH; // 128 bytes per direction
constexpr size_t OPENVPN_KEY2_SIZE = 2 * OPENVPN_KEY_SIZE;                                       // 256 bytes total

size_t KeyDerivation::GetRequiredKeyMaterialSize(CipherAlgorithm cipher,
                                                 HmacAlgorithm hmac)
{
    (void)cipher;
    (void)hmac;
    return OPENVPN_KEY2_SIZE;
}

std::vector<std::uint8_t>
KeyDerivation::DeriveKeyMaterialWithSecret(std::span<const std::uint8_t> secret,
                                           const std::string &label,
                                           std::span<const std::uint8_t> seed,
                                           size_t output_bytes)
{
    if (secret.empty())
        throw std::runtime_error("Secret cannot be empty");

    if (output_bytes == 0)
        throw std::runtime_error("Output size must be > 0");

    // OpenSSL's TLS 1.0 PRF expects the seed to be: label || seed
    // This matches OpenVPN's openvpn_PRF which builds: label || client_seed || server_seed || [session_ids]
    std::vector<std::uint8_t> full_seed;
    full_seed.insert(full_seed.end(), label.begin(), label.end());
    full_seed.insert(full_seed.end(), seed.begin(), seed.end());

    // Use OpenSSL's built-in TLS 1.0 PRF via SslHelp wrapper
    try
    {
        return clv::OpenSSL::SslEvpPkeyCtx::DeriveTls1Prf(
            clv::OpenSSL::SslEvpPkeyCtx::Key(secret.data(), secret.size()),
            full_seed,
            output_bytes);
    }
    catch (const clv::OpenSSL::SslException &e)
    {
        throw std::runtime_error(std::string("TLS 1.0 PRF computation failed: ") + e.what());
    }
}

KeyDerivation::KeyMethod2Result
KeyDerivation::DeriveKeyMethod2(std::span<const std::uint8_t> client_random,
                                std::span<const std::uint8_t> server_random,
                                const SessionId &client_session_id,
                                const SessionId &server_session_id,
                                std::string_view cipher_name)
{
    // Validate input sizes
    if (client_random.size() < CLIENT_KEY_SOURCE_SIZE)
        throw std::runtime_error("Client random too short: " + std::to_string(client_random.size()) + " bytes (expected " + std::to_string(CLIENT_KEY_SOURCE_SIZE) + ")");
    if (server_random.size() < SERVER_KEY_SOURCE_SIZE)
        throw std::runtime_error("Server random too short: " + std::to_string(server_random.size()) + " bytes (expected " + std::to_string(SERVER_KEY_SOURCE_SIZE) + ")");
    if (cipher_name.empty())
        throw std::runtime_error("cipher not configured - required for key derivation");

    // Resolve cipher
    const auto &cipher_info = FindCipherByName(cipher_name); // throws std::invalid_argument

    // Split client_random: 48 bytes pre_master + 32 bytes random1 + 32 bytes random2
    std::span<const uint8_t> pre_master = client_random.subspan(0, 48);
    std::span<const uint8_t> client_random1 = client_random.subspan(48, 32);
    std::span<const uint8_t> client_random2 = client_random.subspan(80, 32);

    // Split server_random: 32 bytes random1 + 32 bytes random2
    std::span<const uint8_t> server_random1 = server_random.subspan(0, 32);
    std::span<const uint8_t> server_random2 = server_random.subspan(32, 32);

    auto client_sid_bytes = client_session_id.ToBytes();
    auto server_sid_bytes = server_session_id.ToBytes();

    spdlog::debug("Two-phase PRF key derivation:");
    spdlog::debug("  client_session_id: {:016x}", client_session_id.value);
    spdlog::debug("  server_session_id: {:016x}", server_session_id.value);
    spdlog::debug("  cipher: {} (key_size={} bytes)", cipher_name, cipher_info.key_size);
    spdlog::debug("  pre_master(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                  pre_master[0],
                  pre_master[1],
                  pre_master[2],
                  pre_master[3],
                  pre_master[4],
                  pre_master[5],
                  pre_master[6],
                  pre_master[7]);
    spdlog::debug("  client_random1(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                  client_random1[0],
                  client_random1[1],
                  client_random1[2],
                  client_random1[3],
                  client_random1[4],
                  client_random1[5],
                  client_random1[6],
                  client_random1[7]);
    spdlog::debug("  server_random1(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                  server_random1[0],
                  server_random1[1],
                  server_random1[2],
                  server_random1[3],
                  server_random1[4],
                  server_random1[5],
                  server_random1[6],
                  server_random1[7]);

    // Phase 1: master secret = PRF(pre_master, "OpenVPN master secret", client_random1 || server_random1)
    std::vector<uint8_t> master_seed;
    master_seed.insert(master_seed.end(), client_random1.begin(), client_random1.end());
    master_seed.insert(master_seed.end(), server_random1.begin(), server_random1.end());

    auto master_secret = DeriveKeyMaterialWithSecret(
        pre_master, "OpenVPN master secret", master_seed, 48);

    // Phase 2: keys = PRF(master, "OpenVPN key expansion", client_random2 || server_random2 || client_sid || server_sid)
    std::vector<uint8_t> expansion_seed;
    expansion_seed.insert(expansion_seed.end(), client_random2.begin(), client_random2.end());
    expansion_seed.insert(expansion_seed.end(), server_random2.begin(), server_random2.end());
    expansion_seed.insert(expansion_seed.end(), client_sid_bytes.begin(), client_sid_bytes.end());
    expansion_seed.insert(expansion_seed.end(), server_sid_bytes.begin(), server_sid_bytes.end());

    size_t key_material_size = GetRequiredKeyMaterialSize(cipher_info.algo, HmacAlgorithm::NONE);

    auto key_material = DeriveKeyMaterialWithSecret(
        master_secret, "OpenVPN key expansion", expansion_seed, key_material_size);

    return KeyMethod2Result(std::move(key_material), cipher_info.algo, HmacAlgorithm::NONE);
}

EncryptionKey KeyDerivation::ExtractDirectionalKey(std::span<const std::uint8_t> material,
                                                   size_t offset,
                                                   CipherAlgorithm cipher,
                                                   HmacAlgorithm hmac)
{
    // OpenVPN key layout (per direction, 128 bytes total):
    // - cipher[64]: first N bytes are cipher key (N depends on algorithm)
    // - hmac[64]: for AEAD ciphers, first 4-12 bytes are implicit IV/salt
    //             for non-AEAD, first N bytes are HMAC key (N depends on algorithm)

    if (offset + OPENVPN_KEY_SIZE > material.size())
        throw std::runtime_error("Offset exceeds material size");

    EncryptionKey key;
    key.cipher_algorithm = cipher;
    key.hmac_algorithm = hmac;

    // Cipher key is at offset+0, up to MAX_CIPHER_KEY_LENGTH bytes
    size_t cipher_key_size = 0;
    if (cipher != CipherAlgorithm::NONE)
    {
        try
        {
            cipher_key_size = GetCipherInfo(cipher).key_size;
        }
        catch (const std::invalid_argument &)
        {
            throw std::runtime_error("Unknown cipher algorithm");
        }
    }

    if (cipher_key_size > 0)
    {
        key.cipher_key.insert(key.cipher_key.end(),
                              material.begin() + offset,
                              material.begin() + offset + cipher_key_size);
    }

    // For AEAD ciphers, the implicit IV comes from the HMAC portion (offset + 64)
    // OpenVPN non-epoch format uses: packet_id (4 bytes) || implicit_iv[4-11] (8 bytes)
    // Where implicit_iv[0-3] = 0 and implicit_iv[4-11] = hmac[0-7]
    // So we need to extract 8 bytes from hmac[0-7] for the implicit IV
    size_t hmac_offset = offset + OPENVPN_MAX_CIPHER_KEY_LENGTH;

    // For AEAD ciphers (GCM, ChaCha20-Poly1305), extract 8 bytes of implicit IV
    // from hmac[0-7]. The full 12-byte nonce is: packet_id || implicit_iv
    if (cipher == CipherAlgorithm::CHACHA20_POLY1305 || cipher == CipherAlgorithm::AES_128_GCM || cipher == CipherAlgorithm::AES_256_GCM)
    {
        // Extract 8 bytes of implicit IV (this goes in nonce[4-11])
        constexpr size_t AEAD_IMPLICIT_IV_SIZE = 8;
        key.cipher_iv.insert(key.cipher_iv.end(),
                             material.begin() + hmac_offset,
                             material.begin() + hmac_offset + AEAD_IMPLICIT_IV_SIZE);

        // Debug: log the extracted salt
        spdlog::debug("ExtractDirectionalKey: offset={}, hmac_offset={}, extracted salt={}",
                      offset,
                      hmac_offset,
                      HexDump(std::span<const std::uint8_t>(material.data() + hmac_offset, AEAD_IMPLICIT_IV_SIZE), 0, ""));
    }

    // For non-AEAD ciphers, extract HMAC key from hmac[] portion
    size_t hmac_key_size = 0;
    if (hmac != HmacAlgorithm::NONE)
    {
        try
        {
            hmac_key_size = GetHmacInfo(hmac).output_size;
        }
        catch (const std::invalid_argument &)
        {
            throw std::runtime_error("Unknown HMAC algorithm");
        }
    }

    if (hmac_key_size > 0)
    {
        // For non-AEAD ciphers, HMAC key comes from hmac[] (no IV conflict)
        key.hmac_key.insert(key.hmac_key.end(),
                            material.begin() + hmac_offset,
                            material.begin() + hmac_offset + hmac_key_size);
    }

    key.is_valid = true;
    return key;
}

bool KeyDerivation::InstallKeys(DataChannel &data_channel,
                                std::span<const std::uint8_t> key_material,
                                CipherAlgorithm cipher_algorithm,
                                HmacAlgorithm hmac_algorithm,
                                std::uint8_t key_id,
                                int transition_window_seconds,
                                PeerRole role)
{
    try
    {
        // Verify we have enough material (256 bytes = sizeof(key2->keys))
        if (key_material.size() < OPENVPN_KEY2_SIZE)
            return false;

        // Extract client→server key (offset 0)
        auto client_to_server = ExtractDirectionalKey(key_material,
                                                      0,
                                                      cipher_algorithm,
                                                      hmac_algorithm);
        client_to_server.key_id = key_id;

        // Extract server→client key (offset 128)
        auto server_to_client = ExtractDirectionalKey(key_material,
                                                      OPENVPN_KEY_SIZE,
                                                      cipher_algorithm,
                                                      hmac_algorithm);
        server_to_client.key_id = key_id;

        // Key directions depend on perspective:
        //   Server: decrypt = client→server, encrypt = server→client
        //   Client: decrypt = server→client, encrypt = client→server
        if (role == PeerRole::Server)
        {
            data_channel.InstallNewKeys(client_to_server, // decrypt
                                        server_to_client, // encrypt
                                        key_id,
                                        transition_window_seconds);
        }
        else
        {
            data_channel.InstallNewKeys(server_to_client, // decrypt
                                        client_to_server, // encrypt
                                        key_id,
                                        transition_window_seconds);
        }

        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

} // namespace clv::vpn::openvpn
