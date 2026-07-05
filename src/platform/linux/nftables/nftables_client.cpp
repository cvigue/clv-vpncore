// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "nftables_client.h"

#include <util/nla_helpers.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace clv::vpn {

namespace {

// ---------------------------------------------------------------------------
// Netlink message construction helpers
// ---------------------------------------------------------------------------

/// Append raw bytes to a buffer
void Append(std::vector<std::uint8_t> &buf, const void *data, std::size_t len)
{
    auto *p = static_cast<const std::uint8_t *>(data);
    buf.insert(buf.end(), p, p + len);
}

/// Pad buffer to 4-byte alignment
void PadTo4(std::vector<std::uint8_t> &buf)
{
    while (buf.size() % 4 != 0)
        buf.push_back(0);
}

/// Start an nlmsghdr at the current offset and return its position
std::size_t BeginNlMsg(std::vector<std::uint8_t> &buf, std::uint16_t type,
                       std::uint16_t flags, std::uint32_t seq)
{
    auto pos = buf.size();
    struct nlmsghdr nlh{};
    nlh.nlmsg_len = sizeof(nlh); // patched by EndNlMsg
    nlh.nlmsg_type = type;
    nlh.nlmsg_flags = flags;
    nlh.nlmsg_seq = seq;
    nlh.nlmsg_pid = 0;
    Append(buf, &nlh, sizeof(nlh));
    return pos;
}

/// Finish the nlmsghdr by patching its length
void EndNlMsg(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf.data() + pos);
    nlh->nlmsg_len = static_cast<std::uint32_t>(buf.size() - pos);
}

/// Append an nfgenmsg sub-header
void AppendNfGenMsg(std::vector<std::uint8_t> &buf, std::uint8_t family,
                    std::uint16_t res_id)
{
    struct nfgenmsg nfg{};
    nfg.nfgen_family = family;
    nfg.version = NFNETLINK_V0;
    nfg.res_id = htons(res_id);
    Append(buf, &nfg, sizeof(nfg));
}

/// Append a netlink attribute (NLA) with arbitrary data
void AppendAttr(std::vector<std::uint8_t> &buf, std::uint16_t type,
                const void *data, std::size_t len)
{
    struct nlattr nla{};
    nla.nla_len = static_cast<std::uint16_t>(NLA_HDRLEN + len);
    nla.nla_type = type;
    Append(buf, &nla, sizeof(nla));
    if (data && len > 0)
        Append(buf, data, len);
    PadTo4(buf);
}

/// Append a string attribute (NUL-terminated)
void AppendAttrStr(std::vector<std::uint8_t> &buf, std::uint16_t type,
                   const char *str)
{
    AppendAttr(buf, type, str, std::strlen(str) + 1);
}

/// Append a u32 attribute in host byte order
void AppendAttrU32(std::vector<std::uint8_t> &buf, std::uint16_t type, std::uint32_t val)
{
    val = htonl(val);
    AppendAttr(buf, type, &val, sizeof(val));
}

/// Start a nested attribute, returning its offset for EndNested()
std::size_t BeginNested(std::vector<std::uint8_t> &buf, std::uint16_t type)
{
    auto pos = buf.size();
    struct nlattr nla{};
    nla.nla_len = 0; // patched by EndNested
    nla.nla_type = type | NLA_F_NESTED;
    Append(buf, &nla, sizeof(nla));
    return pos;
}

/// Close a nested attribute by patching its length
void EndNested(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto *nla = reinterpret_cast<struct nlattr *>(buf.data() + pos);
    nla->nla_len = static_cast<std::uint16_t>(buf.size() - pos);
    PadTo4(buf);
}

/// Compute the nftables message type from subsystem + message
constexpr std::uint16_t NftMsgType(std::uint16_t msg)
{
    return static_cast<std::uint16_t>((NFNL_SUBSYS_NFTABLES << 8) | msg);
}

/// Build a subnet mask of @p len bytes from a CIDR prefix length
void PrefixToNetmask(std::uint8_t prefix_len, std::uint8_t *mask, std::uint32_t len)
{
    std::memset(mask, 0, len);
    for (std::uint32_t i = 0; i < len && prefix_len > 0; ++i)
    {
        if (prefix_len >= 8)
        {
            mask[i] = 0xFF;
            prefix_len -= 8;
        }
        else
        {
            mask[i] = static_cast<std::uint8_t>(0xFF << (8 - prefix_len));
            prefix_len = 0;
        }
    }
}


// ---------------------------------------------------------------------------
// nftables expression builders
// ---------------------------------------------------------------------------

/// Append a "payload" expression — loads bytes from the packet into a register
///   payload @p base, offset @p off, len @p len → dreg @p dreg
void AppendExprPayload(std::vector<std::uint8_t> &buf,
                       std::uint32_t dreg, std::uint32_t base,
                       std::uint32_t offset, std::uint32_t len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "payload");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_PAYLOAD_DREG, dreg);
    AppendAttrU32(buf, NFTA_PAYLOAD_BASE, base);
    AppendAttrU32(buf, NFTA_PAYLOAD_OFFSET, offset);
    AppendAttrU32(buf, NFTA_PAYLOAD_LEN, len);
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "bitwise" expression — dreg = (sreg & mask) ^ xor
///   bitwise sreg → dreg, mask @p mask_bytes, xor zeros
void AppendExprBitwiseBytes(std::vector<std::uint8_t> &buf,
                            std::uint32_t sreg, std::uint32_t dreg,
                            const std::uint8_t *mask_bytes, std::uint32_t len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "bitwise");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_BITWISE_SREG, sreg);
    AppendAttrU32(buf, NFTA_BITWISE_DREG, dreg);
    AppendAttrU32(buf, NFTA_BITWISE_LEN, len);
    // mask
    {
        auto mask_outer = BeginNested(buf, NFTA_BITWISE_MASK);
        AppendAttr(buf, NFTA_DATA_VALUE, mask_bytes, len);
        EndNested(buf, mask_outer);
    }
    // xor: all zeros
    {
        std::vector<std::uint8_t> zeros(len, 0);
        auto xor_outer = BeginNested(buf, NFTA_BITWISE_XOR);
        AppendAttr(buf, NFTA_DATA_VALUE, zeros.data(), len);
        EndNested(buf, xor_outer);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "cmp" expression — compare register against a constant
void AppendExprCmp(std::vector<std::uint8_t> &buf,
                   std::uint32_t sreg, std::uint32_t op,
                   const void *cmp_data, std::size_t cmp_len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "cmp");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_CMP_SREG, sreg);
    AppendAttrU32(buf, NFTA_CMP_OP, op);
    {
        auto cmp_outer = BeginNested(buf, NFTA_CMP_DATA);
        AppendAttr(buf, NFTA_DATA_VALUE, cmp_data, cmp_len);
        EndNested(buf, cmp_outer);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "masq" expression (no attributes needed for basic masquerade)
void AppendExprMasquerade(std::vector<std::uint8_t> &buf)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "masq");
    // masq has optional attrs (flags, proto range) but basic MASQUERADE needs none
    EndNested(buf, expr_outer);
}

/// Append a "meta" expression loading the ingress interface name into @p dreg.
void AppendExprMetaIifname(std::vector<std::uint8_t> &buf, std::uint32_t dreg)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "meta");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_META_DREG, dreg);
    AppendAttrU32(buf, NFTA_META_KEY, NFT_META_IIFNAME);
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append an "immediate" expression setting the verdict register to @p verdict.
void AppendExprImmediateVerdict(std::vector<std::uint8_t> &buf, std::int32_t verdict)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "immediate");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    {
        auto imm_data = BeginNested(buf, NFTA_IMMEDIATE_DATA);
        auto verdict_outer = BeginNested(buf, NFTA_DATA_VERDICT);
        std::uint32_t code = static_cast<std::uint32_t>(verdict);
        AppendAttrU32(buf, NFTA_VERDICT_CODE, code);
        EndNested(buf, verdict_outer);
        EndNested(buf, imm_data);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Pad an interface name to IFNAMSIZ for nft register comparison.
void PadIfname(std::uint8_t *out, const char *ifname)
{
    std::memset(out, 0, IFNAMSIZ);
    std::strncpy(reinterpret_cast<char *>(out), ifname, IFNAMSIZ - 1);
}

class NftBatchBuilder
{
  public:
    explicit NftBatchBuilder(std::size_t reserve = 2048)
    {
        buf_.reserve(reserve);
    }

    void Begin()
    {
        auto pos = BeginNlMsg(buf_, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq_++);
        AppendNfGenMsg(buf_, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf_, pos);
    }

    void AddTable(std::uint8_t family, const char *table_name)
    {
        auto pos = BeginNlMsg(buf_, NftMsgType(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_CREATE, seq_++);
        AppendNfGenMsg(buf_, family, 0);
        AppendAttrStr(buf_, NFTA_TABLE_NAME, table_name);
        EndNlMsg(buf_, pos);
    }

    void AddChain(std::uint8_t family,
                  const char *table_name,
                  const char *chain_name,
                  const char *chain_type,
                  int hooknum,
                  int priority)
    {
        auto pos = BeginNlMsg(buf_, NftMsgType(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_CREATE, seq_++);
        AppendNfGenMsg(buf_, family, 0);
        AppendAttrStr(buf_, NFTA_CHAIN_TABLE, table_name);
        AppendAttrStr(buf_, NFTA_CHAIN_NAME, chain_name);
        AppendAttrStr(buf_, NFTA_CHAIN_TYPE, chain_type);
        {
            auto hook_pos = BeginNested(buf_, NFTA_CHAIN_HOOK);
            AppendAttrU32(buf_, NFTA_HOOK_HOOKNUM, hooknum);
            AppendAttrU32(buf_, NFTA_HOOK_PRIORITY, priority);
            EndNested(buf_, hook_pos);
        }
        EndNlMsg(buf_, pos);
    }

    void BeginRule(std::uint8_t family, const char *table_name, const char *chain_name)
    {
        rule_pos_ = BeginNlMsg(buf_, NftMsgType(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND, seq_++);
        AppendNfGenMsg(buf_, family, 0);
        AppendAttrStr(buf_, NFTA_RULE_TABLE, table_name);
        AppendAttrStr(buf_, NFTA_RULE_CHAIN, chain_name);
        exprs_pos_ = BeginNested(buf_, NFTA_RULE_EXPRESSIONS);
    }

    void EndRule()
    {
        EndNested(buf_, exprs_pos_);
        EndNlMsg(buf_, rule_pos_);
    }

    void End()
    {
        auto pos = BeginNlMsg(buf_, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq_++);
        AppendNfGenMsg(buf_, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf_, pos);
    }

    [[nodiscard]] const std::vector<std::uint8_t> &buffer() const
    {
        return buf_;
    }

    std::vector<std::uint8_t> &buffer_mut()
    {
        return buf_;
    }

  private:
    std::vector<std::uint8_t> buf_;
    std::uint32_t seq_ = 0;
    std::size_t rule_pos_ = 0;
    std::size_t exprs_pos_ = 0;
};

} // namespace

// ---------------------------------------------------------------------------
// NfTablesClient implementation
// ---------------------------------------------------------------------------

NfTablesClient::~NfTablesClient() = default;

NfTablesClient::NftTableDescriptor
NfTablesClient::Descriptor(std::uint8_t family, NftTableRole role)
{
    const bool ipv6 = family == NFPROTO_IPV6;
    if (role == NftTableRole::Nat)
    {
        return {ipv6 ? "clv_vpn_nat6" : "clv_vpn_nat", ipv6 ? 16u : 4u, ipv6 ? 8u : 12u, ipv6 ? 24u : 16u};
    }
    return {ipv6 ? "clv_vpn_filter6" : "clv_vpn_filter", ipv6 ? 16u : 4u, ipv6 ? 8u : 12u, ipv6 ? 24u : 16u};
}

void NfTablesClient::Open()
{
    nlh_.Open(NETLINK_NETFILTER);
}

bool NfTablesClient::SendBatch(const std::vector<std::uint8_t> &batch)
{
    constexpr struct timeval timeout{.tv_sec = 0, .tv_usec = 500000}; // 500ms
    constexpr struct timeval zero{.tv_sec = 0, .tv_usec = 0};

    int fd = nlh_.RawFd();
    if (fd < 0)
        return false;

    // Set a receive timeout so we never block forever.
    // nftables batch transactions may produce zero responses on success
    // (only errors are reported back), so we need a timeout to detect "no error".
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Send the entire batch buffer in one sendmsg
    if (send(fd, batch.data(), batch.size(), 0) < 0)
        return false;

    // Read response — may be NLMSG_ERROR (error or ACK) or may timeout (= success)
    std::vector<std::uint8_t> response(8192);
    ssize_t recv_len = recv(fd, response.data(), response.size(), 0);

    // Remove the timeout so future callers (TableExists) get normal blocking
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    if (recv_len < 0)
    {
        // EAGAIN/EWOULDBLOCK means the timeout expired with no error → success
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return true;
        return false;
    }

    // Walk all messages in the response - any non-zero error means failure
    response.resize(static_cast<std::size_t>(recv_len));
    auto *nlh = reinterpret_cast<struct nlmsghdr *>(response.data());
    auto remaining = static_cast<std::size_t>(recv_len);

    while (NLMSG_OK(nlh, remaining))
    {
        if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
            if (err->error != 0)
                return false; // Kernel reported an error
        }
        nlh = NLMSG_NEXT(nlh, remaining);
    }

    return true;
}

bool NfTablesClient::EnsureMasquerade(std::uint8_t family,
                                      const std::uint8_t *source_network,
                                      std::uint8_t prefix_len)
{
    const auto info = Descriptor(family, NftTableRole::Nat);

    // First remove any existing table to make this idempotent
    if (TableExists(family, NftTableRole::Nat))
        DeleteTable(family, NftTableRole::Nat);

    NftBatchBuilder batch;
    batch.Begin();
    batch.AddTable(family, info.table_name);
    batch.AddChain(family, info.table_name, CHAIN_NAME, "nat", NF_INET_POST_ROUTING, 100);

    batch.BeginRule(family, info.table_name, CHAIN_NAME);
    {
        std::uint8_t mask[16];
        PrefixToNetmask(prefix_len, mask, info.addr_size);

        std::uint8_t network_masked[16];
        for (std::uint32_t i = 0; i < info.addr_size; ++i)
            network_masked[i] = source_network[i] & mask[i];

        auto &buf = batch.buffer_mut();
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.saddr_offset, info.addr_size);
        AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, network_masked, info.addr_size);
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.daddr_offset, info.addr_size);
        AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_NEQ, network_masked, info.addr_size);
        AppendExprMasquerade(buf);
    }
    batch.EndRule();
    batch.End();

    return SendBatch(batch.buffer());
}

bool NfTablesClient::RemoveMasquerade(std::uint8_t family)
{
    return DeleteTable(family, NftTableRole::Nat);
}

bool NfTablesClient::TableExists(std::uint8_t family)
{
    return TableExists(family, NftTableRole::Nat);
}

bool NfTablesClient::FilterTableExists(std::uint8_t family)
{
    return TableExists(family, NftTableRole::Filter);
}

bool NfTablesClient::TableExists(std::uint8_t family, NftTableRole role)
{
    const auto info = Descriptor(family, role);

    int fd = nlh_.RawFd();
    if (fd < 0)
        return false;

    std::vector<std::uint8_t> buf;
    buf.reserve(256);

    struct nlmsghdr nlh{};
    nlh.nlmsg_type = NftMsgType(NFT_MSG_GETTABLE);
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_pid = 0;
    Append(buf, &nlh, sizeof(nlh));

    AppendNfGenMsg(buf, family, 0);
    AppendAttrStr(buf, NFTA_TABLE_NAME, info.table_name);

    auto *hdr = reinterpret_cast<struct nlmsghdr *>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());

    struct timeval tv{.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(fd, buf.data(), buf.size(), 0) < 0)
        return false;

    std::vector<std::uint8_t> response(8192);
    ssize_t recv_len = recv(fd, response.data(), response.size(), 0);

    struct timeval zero{.tv_sec = 0, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    if (recv_len < 0)
        return false;

    if (static_cast<std::size_t>(recv_len) < sizeof(struct nlmsghdr))
        return false;

    auto *resp = reinterpret_cast<struct nlmsghdr *>(response.data());
    if (resp->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
        return err->error == 0;
    }

    return true;
}

bool NfTablesClient::DeleteTable(std::uint8_t family, NftTableRole role)
{
    const auto info = Descriptor(family, role);

    std::vector<std::uint8_t> buf;
    buf.reserve(512);
    std::uint32_t seq = 0;

    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_DELTABLE), NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, family, 0);
        AppendAttrStr(buf, NFTA_TABLE_NAME, info.table_name);
        EndNlMsg(buf, pos);
    }

    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    return SendBatch(buf);
}

bool NfTablesClient::EnsureIntraPoolDrop(std::uint8_t family, const char *ifname,
                                         const std::uint8_t *pool_network,
                                         std::uint8_t prefix_len,
                                         const std::uint8_t *bridge_ip)
{
    if (!ifname || !ifname[0] || !pool_network || !bridge_ip)
        return false;

    const auto info = Descriptor(family, NftTableRole::Filter);

    if (TableExists(family, NftTableRole::Filter))
        DeleteTable(family, NftTableRole::Filter);

    std::uint8_t mask[16];
    PrefixToNetmask(prefix_len, mask, info.addr_size);

    std::uint8_t network_masked[16];
    for (std::uint32_t i = 0; i < info.addr_size; ++i)
        network_masked[i] = pool_network[i] & mask[i];

    std::uint8_t ifname_padded[IFNAMSIZ];
    PadIfname(ifname_padded, ifname);

    NftBatchBuilder batch(4096);
    batch.Begin();
    batch.AddTable(family, info.table_name);
    batch.AddChain(family, info.table_name, FILTER_CHAIN_NAME, "filter", NF_INET_FORWARD, 0);

    batch.BeginRule(family, info.table_name, FILTER_CHAIN_NAME);
    {
        auto &buf = batch.buffer_mut();
        AppendExprMetaIifname(buf, NFT_REG_1);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, ifname_padded, IFNAMSIZ);
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.saddr_offset, info.addr_size);
        AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, network_masked, info.addr_size);
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.daddr_offset, info.addr_size);
        AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, network_masked, info.addr_size);
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.daddr_offset, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_NEQ, bridge_ip, info.addr_size);
        AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, info.saddr_offset, info.addr_size);
        AppendExprCmp(buf, NFT_REG_1, NFT_CMP_NEQ, bridge_ip, info.addr_size);
        AppendExprImmediateVerdict(buf, NF_DROP);
    }
    batch.EndRule();
    batch.End();

    return SendBatch(batch.buffer());
}

bool NfTablesClient::RemoveIntraPoolDrop(std::uint8_t family)
{
    return DeleteTable(family, NftTableRole::Filter);
}

} // namespace clv::vpn
