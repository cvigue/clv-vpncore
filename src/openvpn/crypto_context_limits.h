// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CRYPTO_CONTEXT_LIMITS_H
#define CLV_VPN_OPENVPN_CRYPTO_CONTEXT_LIMITS_H

/**
 * @file crypto_context_limits.h
 * @brief Legacy §7.4 outbound limits (packet-ID wrap + AES-GCM usage).
 *
 * Phase A of epoch RFC remediation: no wire-format changes.  Matches OpenVPN
 * PACKET_ID_WRAP_TRIGGER and RFC §7.2.1 (q + s ≤ 2³⁶) with reneg at 80%.
 *
 * q = AEAD invocations (one per outbound packet).
 * s = 128-bit cipher blocks over plaintext, legacy P_DATA_V2 AAD (8 B), and tag (16 B).
 */

#include "openvpn/crypto_algorithms.h"

#include <cstddef>
#include <cstdint>

namespace clv::vpn::openvpn {

/** OpenVPN legacy soft-reset trigger (packet_id.h PACKET_ID_WRAP_TRIGGER). */
constexpr std::uint32_t kPacketIdWrapTrigger = 0xFF000000u;

/** RFC §7.2.1 budget reference max plaintext size (bytes). */
constexpr std::size_t kLegacyAeadMaxPlaintextBytes = 1600;

/** Legacy §7.4 P_DATA_V2 AAD: opcode/key_id/peer_id (4) + packet_id (4). */
constexpr std::size_t kLegacyDataV2AadBytes = 8;

/** Legacy §7.4 AEAD authentication tag length (bytes). */
constexpr std::size_t kLegacyDataV2TagBytes = 16;

/** RFC §7.2.1 hard limit: q + s ≤ 2³⁶. */
constexpr std::uint64_t kLegacyAeadUsageLimit = (1ULL << 36);

/** Peer-review decision: trigger TLS soft reset at 80% of the GCM budget. */
constexpr std::uint64_t kLegacyAeadUsageRenegThreshold = (kLegacyAeadUsageLimit * 80) / 100;

[[nodiscard]] inline constexpr bool IsLegacyAeadUsageLimited(CipherAlgorithm algo) noexcept
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
    case CipherAlgorithm::AES_256_GCM:
        return true;
    default:
        return false;
    }
}

/** Round @p byte_len up to 128-bit GCM block count. */
[[nodiscard]] inline constexpr std::uint64_t LegacyAeadPlaintextBlocks(std::size_t byte_len) noexcept
{
    return (byte_len + 15) / 16;
}

/** s-term blocks for one legacy §7.4 encrypt (plaintext + AAD + tag). */
[[nodiscard]] inline constexpr std::uint64_t LegacyAeadCipherBlocksPerEncrypt(
    std::size_t plaintext_len) noexcept
{
    return LegacyAeadPlaintextBlocks(plaintext_len) + LegacyAeadPlaintextBlocks(kLegacyDataV2AadBytes)
           + LegacyAeadPlaintextBlocks(kLegacyDataV2TagBytes);
}

[[nodiscard]] inline constexpr std::uint64_t LegacyAeadTotalUsage(std::uint64_t invocations,
                                                                  std::uint64_t blocks) noexcept
{
    return invocations + blocks;
}

[[nodiscard]] inline constexpr bool LegacyAeadNeedsReneg(std::uint64_t invocations,
                                                         std::uint64_t blocks) noexcept
{
    return LegacyAeadTotalUsage(invocations, blocks) >= kLegacyAeadUsageRenegThreshold;
}

[[nodiscard]] inline constexpr bool LegacyAeadIsBlocked(std::uint64_t invocations,
                                                        std::uint64_t blocks) noexcept
{
    return LegacyAeadTotalUsage(invocations, blocks) >= kLegacyAeadUsageLimit;
}

/** Accumulated q + s counters for one active encrypt key. */
struct LegacyAeadUsage
{
    std::uint64_t invocations = 0;
    std::uint64_t blocks = 0;

    [[nodiscard]] std::uint64_t Total() const noexcept
    {
        return LegacyAeadTotalUsage(invocations, blocks);
    }

    [[nodiscard]] bool NeedsReneg() const noexcept
    {
        return LegacyAeadNeedsReneg(invocations, blocks);
    }

    [[nodiscard]] bool IsBlocked() const noexcept
    {
        return LegacyAeadIsBlocked(invocations, blocks);
    }

    void Reset() noexcept
    {
        invocations = 0;
        blocks = 0;
    }
};

/** q + s budget charged for one legacy encrypt. */
struct LegacyAeadUsageDelta
{
    std::uint64_t invocations = 0;
    std::uint64_t blocks = 0;

    [[nodiscard]] std::uint64_t Total() const noexcept
    {
        return invocations + blocks;
    }
};

[[nodiscard]] inline constexpr LegacyAeadUsageDelta LegacyAeadUsageForEncrypt(
    std::size_t plaintext_len) noexcept
{
    return {.invocations = 1, .blocks = LegacyAeadCipherBlocksPerEncrypt(plaintext_len)};
}

/** Apply one encrypt to @p usage (single source of truth for q+s arithmetic). */
inline void LegacyAeadApplyEncrypt(LegacyAeadUsage &usage, std::size_t plaintext_len) noexcept
{
    const auto delta = LegacyAeadUsageForEncrypt(plaintext_len);
    usage.invocations += delta.invocations;
    usage.blocks += delta.blocks;
}

/** Limit flags after recording usage (shared by CryptoContext and unit tests). */
struct LegacyAeadLimitFlags
{
    bool needs_reneg = false;
    bool is_blocked = false;
};

[[nodiscard]] inline constexpr LegacyAeadLimitFlags LegacyAeadLimitFlagsForUsage(
    std::uint64_t invocations,
    std::uint64_t blocks) noexcept
{
    return {.needs_reneg = LegacyAeadNeedsReneg(invocations, blocks),
            .is_blocked = LegacyAeadIsBlocked(invocations, blocks)};
}

/**
 * @brief Non-atomic tracker for unit tests (wraps @c LegacyAeadUsage).
 *
 * ChaCha20-Poly1305 is unlimited per RFC §7.2.1; callers skip recording for it.
 */
struct LegacyAeadUsageTracker
{
    LegacyAeadUsage usage{};

    void RecordEncrypt(std::size_t plaintext_len) noexcept
    {
        LegacyAeadApplyEncrypt(usage, plaintext_len);
    }

    [[nodiscard]] std::uint64_t TotalUsage() const noexcept
    {
        return usage.Total();
    }

    [[nodiscard]] bool NeedsReneg() const noexcept
    {
        return usage.NeedsReneg();
    }

    [[nodiscard]] bool IsBlocked() const noexcept
    {
        return usage.IsBlocked();
    }

    void Reset() noexcept
    {
        usage.Reset();
    }
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_CRYPTO_CONTEXT_LIMITS_H
