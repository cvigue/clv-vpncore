// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TLS_CRYPT_TEST_UTIL_H
#define CLV_VPN_TLS_CRYPT_TEST_UTIL_H

#include "openvpn/packet.h"

#include <util/byte_packer.h>

#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace clv::vpn::test {

/// Deterministic OpenVPN static key PEM (256 bytes). Test-only — not for production.
inline std::string_view TlsCryptTestKeyPem()
{
    static constexpr std::string_view kKey = R"(#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
ae21eb58f6a3b3621d924a795437603d
69677066303aedd8d822b5281737c3e1
a9adc19f62fc329c78b05a715b92e6ef
474e44d870596a071c9c2b7b006f7a50
12fd11f766f3768aec84b34eca921630
728537a9e42a76dbbfc6113d81305f6e
8c9c0253215ec5f1e09bb0c1eba9275f
80bc6d57a11a899288ca14c0f55e5a28
d576be4c86d593fbbe9ed2d55346c10c
59ad6d1479284223561535290e5db9aa
076e4b085fd73704f426e7e758aa5108
061407b814ef04e230af53ae67068f8b
148b3f13af910687d92c37bcce262e74
90aa3773149dfe6d894b1af094d0a955
fc20e02843f573014fd381b10db82b67
3251a2cf4128652dfdb072cd1438b88d
-----END OpenVPN Static key V1-----
)";
    return kKey;
}

inline std::vector<std::uint8_t> ParseTlsCryptTestKeyData(std::string_view pem)
{
    std::vector<std::uint8_t> data;
    data.reserve(256);

    bool in_key = false;
    std::istringstream stream{std::string(pem)};
    std::string line;
    while (std::getline(stream, line))
    {
        if (line.find("-----BEGIN") != std::string::npos)
        {
            in_key = true;
            continue;
        }
        if (line.find("-----END") != std::string::npos)
            break;
        if (!in_key)
            continue;

        for (std::size_t i = 0; i + 1 < line.size(); ++i)
        {
            const auto hi = static_cast<unsigned char>(line[i]);
            const auto lo = static_cast<unsigned char>(line[i + 1]);
            if (std::isxdigit(hi) && std::isxdigit(lo))
            {
                data.push_back(static_cast<std::uint8_t>(std::stoul(line.substr(i, 2), nullptr, 16)));
                ++i;
            }
        }
    }

    return data;
}

inline const std::vector<std::uint8_t> &TlsCryptTestKeyData()
{
    static const std::vector<std::uint8_t> kData = ParseTlsCryptTestKeyData(TlsCryptTestKeyPem());
    return kData;
}

inline const std::string &TlsCryptTestKeyPemString()
{
    static const std::string kPem(TlsCryptTestKeyPem());
    return kPem;
}

/// tls-crypt plaintext: [opcode_byte][session_id:8][payload...]
inline std::vector<std::uint8_t> MakeTlsCryptPlaintext(openvpn::Opcode opcode,
                                                       std::uint64_t session_id,
                                                       std::span<const std::uint8_t> payload = {},
                                                       std::uint8_t key_id = 0)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(openvpn::MakeOpcodeByte(opcode, key_id));
    const auto sid_bytes = clv::netcore::uint_to_bytes(session_id);
    buf.insert(buf.end(), sid_bytes.begin(), sid_bytes.end());
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}

} // namespace clv::vpn::test

#endif // CLV_VPN_TLS_CRYPT_TEST_UTIL_H
