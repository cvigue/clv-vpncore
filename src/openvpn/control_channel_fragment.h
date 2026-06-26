// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CONTROL_CHANNEL_FRAGMENT_H
#define CLV_VPN_OPENVPN_CONTROL_CHANNEL_FRAGMENT_H

#include <cstdint>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn::detail {

/**
 * @brief Group TLS records from a flat byte stream into MTU-sized chunks.
 *
 * Parses TLS record headers (5 bytes each: type|version(2)|length(2)) and
 * accumulates complete records into fragments, flushing to the output vector
 * whenever adding the next record would exceed `mtu`.
 *
 * @param tls_data  Byte stream of TLS records to process.
 * @param mtu       Maximum fragment payload size in bytes.
 * @return          A pair of:
 *                    - groups: each element is a raw byte payload for one packet.
 *                    - truncated: true if a malformed record header was encountered
 *                      (declared length extends past end of buffer), causing early exit.
 */
[[nodiscard]] inline std::pair<std::vector<std::vector<std::uint8_t>>, bool>
GroupTlsRecords(std::span<const std::uint8_t> tls_data, std::size_t mtu)
{
    std::vector<std::vector<std::uint8_t>> groups;
    std::vector<std::uint8_t> current;
    bool truncated = false;

    for (std::size_t pos = 0; pos + 5 <= tls_data.size();)
    {
        // TLS record header: [type:1][version:2][length:2] (big-endian)
        std::uint16_t record_length = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tls_data[pos + 3]) << 8) | static_cast<std::uint16_t>(tls_data[pos + 4]));
        std::size_t total = 5 + record_length;

        if (pos + total > tls_data.size())
        {
            truncated = true;
            break;
        }

        // Flush current group if this record would exceed MTU.
        if (!current.empty() && current.size() + total > mtu)
        {
            groups.push_back(std::move(current));
            current.clear();
        }

        current.insert(current.end(),
                       tls_data.data() + pos,
                       tls_data.data() + pos + total);
        pos += total;
    }

    if (!current.empty())
        groups.push_back(std::move(current));

    return {std::move(groups), truncated};
}

} // namespace clv::vpn::openvpn::detail

#endif // CLV_VPN_OPENVPN_CONTROL_CHANNEL_FRAGMENT_H
