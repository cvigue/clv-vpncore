// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DATA_TRANSPORT_H
#define CLV_VPN_DATA_TRANSPORT_H

/**
 * @file data_transport.h
 * @brief Composed data-transport wrapper — inherits adapter policies.
 *
 * Policy-based design (Alexandrescu-style):
 *   - DataAdapterT<Self>     CRTP base, data→control (called from hot-path threads)
 *   - ControlAdapterT<Self>  CRTP base, control→data (called from control io_context)
 *
 * DataTransport publicly inherits both, giving callers a flat API with zero
 * runtime cost.  The channel sees adapter methods via CRTP back-ref.
 *
 * Construction: pass the config bundle directly — ControlAdapterT is constructed
 * in the initializer list (common setup, no derived() calls), then
 * ConstructDataChannel() is called from the constructor body once all members exist.
 *
 * @tparam DataChannelTpl    Concrete data-channel template (e.g. ClientTcpChannel).
 * @tparam DataAdapterT      Data-side adapter CRTP template.
 * @tparam ControlAdapterT   Control-side adapter CRTP template.
 */

#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/packet.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

namespace clv::vpn {

/**
 * @brief Composed data-transport with policy-based adapter inheritance.
 *
 * Publicly inherits DataAdapterT<Self> (data→control) and ControlAdapterT<Self>
 * (control→data), exposing their interfaces as first-class methods.
 *
 * Accepts the adapter config bundle as a constructor argument: constructs
 * ControlAdapterT in the initializer list, then calls ConstructDataChannel()
 * from the body — no two-phase init required.
 *
 * Non-copyable, non-movable: the channel holds references to adapter members.
 *
 * @tparam DataChannelTpl    Concrete data-channel template (e.g. ClientTcpChannel).
 * @tparam DataAdapterT      Data-side adapter CRTP template.
 * @tparam ControlAdapterT   Control-side adapter CRTP template.
 */
template <template <typename> typename DataChannelTpl,
          template <typename> typename DataAdapterT,
          template <typename> typename ControlAdapterT>
class DataTransport
    : public DataAdapterT<DataTransport<DataChannelTpl, DataAdapterT, ControlAdapterT>>,
      public ControlAdapterT<DataTransport<DataChannelTpl, DataAdapterT, ControlAdapterT>>
{
    using Self = DataTransport<DataChannelTpl, DataAdapterT, ControlAdapterT>;
    using DataBase = DataAdapterT<Self>;
    using ControlBase = ControlAdapterT<Self>;
    using DataChannelT = DataChannelTpl<DataBase>;
    friend DataBase;    // Let CRTP base access channel()
    friend ControlBase; // Let CRTP base access channel()

  public:
    using channel_type = DataChannelT;

  public:
    // -- Construction ---------------------------------------------------------

    /**
     * @brief Construct and fully initialize.
     *
     * ControlAdapterT is constructed with cfg in the initializer list (its
     * data members are ready but derived() is not yet valid).  Once the
     * DataTransport body runs all members exist and ChannelArgs() (defined
     * in ControlAdapterT) can safely return a reference-tuple that is
     * consumed immediately here — do not store the ChannelArgs() return value.
     */
    template <typename Cfg>
    explicit DataTransport(Cfg cfg)
        : ControlBase(std::move(cfg))
    {
        auto apply_fn = [this](auto &&...args)
        {
            channel_.emplace(std::forward<decltype(args)>(args)...);
        };

        std::apply(apply_fn, this->ChannelArgs());
        channel_->SetAdapter(static_cast<DataBase &>(*this));
    }

    DataTransport(const DataTransport &) = delete;
    DataTransport &operator=(const DataTransport &) = delete;
    DataTransport(DataTransport &&) = delete;
    DataTransport &operator=(DataTransport &&) = delete;

    // -- Channel-generic data operations (delegate directly) ------------------

    asio::awaitable<void> StartDataPath()
    {
        return channel_->StartDataPath();
    }
    void StopDataPath()
    {
        channel_->StopDataPath();
    }

    asio::awaitable<void> DeliverDecryptedPacket(std::vector<std::uint8_t> plaintext)
    {
        return channel_->DeliverDecryptedPacket(std::move(plaintext));
    }

    asio::awaitable<void> ProcessIncomingDataPacket(
        Connection *session, const openvpn::OpenVpnPacket &packet)
    {
        return channel_->ProcessIncomingDataPacket(session, packet);
    }

    std::span<std::uint8_t> DecryptAndStripInPlace(
        Connection *session, std::span<std::uint8_t> datagram)
    {
        return channel_->DecryptAndStripInPlace(session, datagram);
    }

    void SetBatchSize(std::size_t newSize)
    {
        channel_->SetBatchSize(newSize);
    }
    std::size_t GetBatchSize() const
    {
        return channel_->GetBatchSize();
    }

    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        return channel_->InstallKeys(session, key_material, cipher_algo, hmac_algo, key_id);
    }

    // -- Keepalive (delegate directly) ----------------------------------------

    // Client-side: called by KeepaliveLoop with no session context.
    asio::awaitable<void> SendKeepalivePing()
    {
        return channel_->SendKeepalivePing();
    }

    std::chrono::steady_clock::time_point LastTxTime() const
    {
        return channel_->LastTxTime();
    }

    // Server-side: called by udp/tcp RunKeepaliveMonitor with session context.
    asio::awaitable<void> SendKeepAlivePing(Connection *session)
    {
        return channel_->SendKeepAlivePing(session);
    }

    asio::awaitable<void> RunKeepaliveMonitor()
    {
        return channel_->RunKeepaliveMonitor();
    }

    void StopKeepaliveMonitor()
    {
        channel_->StopKeepaliveMonitor();
    }

    // -- Stats ----------------------------------------------------------------

    DataPathStats SnapshotStats() const
    {
        return channel_->SnapshotStats();
    }

    // -- Channel access (for CRTP bases and direct queries) -------------------

    DataChannelT &channel() noexcept
    {
        return const_cast<DataChannelT &>(std::as_const(*this).channel());
    }
    const DataChannelT &channel() const noexcept
    {
        assert(channel_.has_value());
        return *channel_;
    }

  private:
    std::optional<DataChannelT> channel_;
};

} // namespace clv::vpn

#endif // CLV_VPN_DATA_TRANSPORT_H
