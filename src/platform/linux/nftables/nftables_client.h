// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NFTABLES_CLIENT_H
#define CLV_VPN_NFTABLES_CLIENT_H

#include <util/netlink_helper.h>

#include <cstdint>
#include <string>
#include <vector>

namespace clv::vpn {

/**
 * @brief Netlink-based nftables client for adding/removing NAT / filter rules.
 *
 * Communicates directly with the kernel's nf_tables subsystem via
 * @c NETLINK_NETFILTER — no shelling out to @c iptables / @c nft.
 *
 * Tables are keyed by hub @p ifname so multiple TunnelZone hub attachments
 * do not clobber each other (e.g. @c clv_vpn_nat_tun0, @c clv_vpn_filter_tun1).
 *
 * @note Requires @c CAP_NET_ADMIN.
 *
 * @par Threading
 * Not thread-safe. Intended for single-threaded VPN lifecycle use.
 */
class NfTablesClient
{
  public:
    /** Address-family constants (avoids pulling linux/netfilter.h into callers) */
    static constexpr std::uint8_t kIPv4 = 2;  // NFPROTO_IPV4
    static constexpr std::uint8_t kIPv6 = 10; // NFPROTO_IPV6

    /** @brief Default-construct an unopened nftables client. */
    NfTablesClient() = default;
    /** @brief Close the netlink socket if open. */
    ~NfTablesClient();

    NfTablesClient(const NfTablesClient &) = delete;
    NfTablesClient &operator=(const NfTablesClient &) = delete;
    /** @brief Move-construct an nftables client. */
    NfTablesClient(NfTablesClient &&) noexcept = default;
    /** @brief Move-assign an nftables client. */
    NfTablesClient &operator=(NfTablesClient &&) noexcept = default;

    /**
     * @brief Build the nft table name for a hub attachment.
     *
     * Sanitizes @p ifname to `[A-Za-z0-9_]`; used by unit tests and Ensure*.
     */
    [[nodiscard]] static std::string TableName(std::uint8_t family,
                                               bool filter,
                                               const char *ifname);

    /**
     * @brief Open the netlink socket.
     * @throws std::system_error on failure
     */
    void Open();

    /**
     * @brief Ensure a MASQUERADE rule for @p ifname's dedicated NAT table.
     *
     * Creates (or re-creates) @c clv_vpn_nat[_6]_<ifname> with a postrouting
     * chain that masquerades traffic from @p source_network / @p prefix_len
     * whose destination is NOT the same subnet.
     */
    bool EnsureMasquerade(std::uint8_t family,
                          const char *ifname,
                          const std::uint8_t *source_network,
                          std::uint8_t prefix_len);

    /** Remove the masquerade table for @p ifname / @p family. */
    bool RemoveMasquerade(std::uint8_t family, const char *ifname);

    /** True if the NAT table for @p ifname / @p family exists. */
    bool TableExists(std::uint8_t family, const char *ifname);

    /**
     * @brief Ensure a forward-hook DROP rule for intra-pool traffic on @p ifname.
     *
     * Owns @c clv_vpn_filter[_6]_<ifname> only — other hubs' tables are untouched.
     */
    bool EnsureIntraPoolDrop(std::uint8_t family,
                             const char *ifname,
                             const std::uint8_t *pool_network,
                             std::uint8_t prefix_len,
                             const std::uint8_t *bridge_ip);

    /** Remove the filter table for @p ifname / @p family. */
    bool RemoveIntraPoolDrop(std::uint8_t family, const char *ifname);

    /** True if the filter table for @p ifname / @p family exists. */
    bool FilterTableExists(std::uint8_t family, const char *ifname);

  private:
    enum class NftTableRole
    {
        Nat,
        Filter,
    };

    struct NftTableDescriptor
    {
        std::string table_name;
        std::uint32_t addr_size;
        std::uint32_t saddr_offset;
        std::uint32_t daddr_offset;
    };

    static NftTableDescriptor Descriptor(std::uint8_t family,
                                         NftTableRole role,
                                         const char *ifname);
    bool TableExists(std::uint8_t family, NftTableRole role, const char *ifname);
    bool DeleteTable(std::uint8_t family, NftTableRole role, const char *ifname);

    static constexpr const char *CHAIN_NAME = "postrouting";
    static constexpr const char *FILTER_CHAIN_NAME = "forward";

    bool SendBatch(const std::vector<std::uint8_t> &batch);

    clv::netlink::NetlinkHelper nlh_;
};

} // namespace clv::vpn

#endif // CLV_VPN_NFTABLES_CLIENT_H
