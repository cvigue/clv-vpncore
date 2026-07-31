// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TUN_TUN_DEVICE_H
#define CLV_VPN_TUN_TUN_DEVICE_H

#include <asio.hpp>
#include <array>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace clv::vpn::tun {

/**
 * @brief IP packet structure
 *
 * Represents a raw IP packet (IPv4 or IPv6) read from or written to
 * the TUN device.
 */
struct IpPacket
{
    /** Raw IP packet data (including IP header) */
    std::vector<std::uint8_t> data;

    /** IP version (4 or 6), extracted from first nibble */
    std::uint8_t version() const
    {
        return data.empty() ? 0 : (data[0] >> 4);
    }

    /** Total packet length */
    std::size_t size() const
    {
        return data.size();
    }

    /** Check if packet is valid (has at least IP header) */
    bool is_valid() const
    {
        if (data.size() < 20)
            return false; // Too short for IPv4
        std::uint8_t ver = version();
        return ver == 4 || ver == 6;
    }
};

/**
 * @brief TUN/TAP virtual network device
 *
 * Owns and configures a Linux TUN fd (/dev/net/tun): create, addresses, MTU,
 * up/down, close. Provides single-packet async I/O (`ReadPacket` /
 * `WritePacket`) for TCP and other one-frame-at-a-time paths.
 *
 * High-PPS engines (e.g. UdpCore) should borrow `NativeHandle()` for
 * non-blocking `::read` / `::write` and a caller-owned `dup` + Asio wait —
 * that is the supported contract, not a layering bypass.
 *
 * Usage:
 * @code
 * TunDevice tun(io_context);
 * tun.Create("tun0");
 * tun.SetAddress("10.8.0.1", 24);
 * tun.SetMtu(1500);
 * tun.BringUp();
 *
 * // Async single-packet I/O
 * auto pkt = co_await tun.ReadPacket();
 * co_await tun.WritePacket(pkt);
 *
 * // Or borrow the fd for an engine fill/write loop
 * int fd = tun.NativeHandle();
 * @endcode
 */
class TunDevice
{
  public:
    /** Maximum MTU for TUN interface */
    static constexpr std::uint16_t MAX_MTU = 9000;

    /** Default MTU (typical for VPN) */
    static constexpr std::uint16_t DEFAULT_MTU = 1500;

    /** Maximum packet size to read (includes overhead) */
    static constexpr std::size_t MAX_PACKET_SIZE = MAX_MTU + 4; // +4 for possible flags

    /**
     * @brief Construct TUN device manager
     * @param io_context ASIO I/O context for async operations
     */
    explicit TunDevice(asio::io_context &io_context);

    /**
     * @brief Destructor - closes device if open
     */
    ~TunDevice();

    // Non-copyable
    TunDevice(const TunDevice &) = delete;
    TunDevice &operator=(const TunDevice &) = delete;

    // Movable
    /** @brief Move-construct a TunDevice (transfers FD ownership). */
    TunDevice(TunDevice &&) noexcept;
    /** @brief Move-assign a TunDevice (transfers FD ownership). */
    TunDevice &operator=(TunDevice &&) noexcept;

    /**
     * @brief Create TUN device
     *
     * Opens /dev/net/tun and creates a TUN interface.
     * Requires CAP_NET_ADMIN or root privileges on Linux.
     *
     * @param dev_name Device name (e.g., "tun0"). If empty, kernel assigns name.
     * @return Actual device name created
     * @throws std::system_error on failure
     */
    std::string Create(const std::string &dev_name = "", int mode = O_RDWR | O_NONBLOCK);

    /**
     * @brief Set IP address and prefix length
     *
     * Configures the interface IP address using SIOCGIFADDR/SIOCSIFADDR ioctls.
     *
     * @param addr IPv4 address in dotted notation (e.g., "10.8.0.1")
     * @param prefix_len Network prefix length (e.g., 24 for /24)
     * @throws std::system_error on failure
     */
    void SetAddress(const std::string &addr, std::uint8_t prefix_len);

    /**
     * @brief Add an IPv6 address to the interface
     *
     * Uses the Linux in6_ifreq ioctl to add a global/ULA IPv6 address
     * alongside the existing IPv4 configuration.
     *
     * @param addr IPv6 address string (e.g., "fd00::1")
     * @param prefix_len Prefix length (e.g., 112)
     * @throws std::system_error on failure
     */
    void AddIpv6Address(const std::string &addr, std::uint8_t prefix_len);

    /**
     * @brief Set MTU (Maximum Transmission Unit)
     *
     * @param mtu MTU size in bytes (must be <= MAX_MTU)
     * @throws std::system_error on failure
     * @throws std::invalid_argument if mtu > MAX_MTU
     */
    void SetMtu(std::uint16_t mtu);

    /**
     * @brief Set TX queue length
     *
     * Controls how many packets the kernel will queue for transmission
     * on this interface before dropping. Higher values absorb bursts
     * but add latency.
     *
     * @param len Queue length in packets
     * @throws std::system_error on failure
     */
    void SetTxQueueLen(int len);

    /**
     * @brief Bring interface up (IFF_UP flag)
     *
     * Makes the interface active and able to send/receive packets.
     *
     * @throws std::system_error on failure
     */
    void BringUp();

    /**
     * @brief Bring interface down
     *
     * Deactivates the interface.
     *
     * @throws std::system_error on failure
     */
    void BringDown();

    /**
     * @brief Close the TUN device
     *
     * Closes the file descriptor and releases the device.
     * Called automatically by destructor.
     */
    void Close();

    /**
     * @brief Check if device is open
     */
    bool IsOpen() const;

    /**
     * @brief Get device name
     */
    const std::string &GetName() const
    {
        return dev_name_;
    }

    /**
     * @brief Get current MTU
     */
    std::uint16_t GetMtu() const
    {
        return mtu_;
    }

    /**
     * @brief Read packet from TUN device (async)
     *
     * Reads one IP packet from the TUN device using ASIO async operations.
     *
     * @return IP packet read from device
     * @throws asio::system_error on I/O error
     */
    asio::awaitable<IpPacket> ReadPacket();

    /**
     * @brief Read one TUN packet directly into @p dest (no intermediate copy).
     * @param dest Destination for IP packet bytes (must be non-empty)
     * @return Bytes read into @p dest
     * @throws asio::system_error on I/O error
     */
    asio::awaitable<std::size_t> ReadPacketInto(std::span<std::uint8_t> dest);

    /**
     * @brief Non-blocking TUN read into @p dest; 0 if would block.
     * @details Uses poll(0)+read; does not change the descriptor's blocking
     *          mode. Used to extend a TCP TX batch after an awaited ReadPacketInto.
     *          Must not race an outstanding async_read on this device.
     */
    std::size_t TryReadPacketInto(std::span<std::uint8_t> dest);

    /**
     * @brief Write packet to TUN device (async)
     *
     * Writes one IP packet to the TUN device using ASIO async operations.
     *
     * @param pkt Packet to write
     * @throws asio::system_error on I/O error
     */
    asio::awaitable<void> WritePacket(const IpPacket &pkt);

    /**
     * @brief Write raw IP bytes to TUN (async), no intermediate IpPacket copy.
     * @param data Non-empty IPv4/IPv6 packet bytes
     */
    asio::awaitable<void> WritePacket(std::span<const std::uint8_t> data);

    /**
     * @brief Borrow the native TUN file descriptor
     *
     * Supported escape hatch for high-PPS paths (non-blocking `::read` /
     * `::write`, caller-owned `dup` + Asio wait). TunDevice retains ownership;
     * do not close this fd.
     *
     * @return Native fd, or -1 if not open
     */
    int NativeHandle() const;

  private:
    /** ASIO I/O context */
    asio::io_context &io_context_;

    /** ASIO stream descriptor for async I/O */
    std::unique_ptr<asio::posix::stream_descriptor> stream_;

    /** Device name (e.g., "tun0") */
    std::string dev_name_;

    /** Current MTU */
    std::uint16_t mtu_ = DEFAULT_MTU;

    /**
     * Read buffer for ReadPacket().
     * Invariant: only one coroutine reads via the owning stream_ at a time.
     */
    std::array<std::uint8_t, MAX_PACKET_SIZE> read_buffer_;
};

} // namespace clv::vpn::tun

#endif // CLV_VPN_TUN_TUN_DEVICE_H
