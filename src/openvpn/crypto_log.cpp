// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/crypto_log.h"

#include <HelpSslPkeyCrypto.h>
#include <log_utils.h>

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>

namespace clv::vpn::openvpn {

std::string KeyMaterialFingerprint(std::span<const std::uint8_t> material,
                                   std::size_t digest_prefix_bytes)
{
    if (material.empty())
        return "none";

    const auto digest = clv::OpenSSL::Sha256(material);
    const auto prefix = std::min(digest_prefix_bytes, digest.size());
    return clv::HexDump(std::span<const std::uint8_t>(digest.data(), prefix), prefix, "");
}

} // namespace clv::vpn::openvpn
