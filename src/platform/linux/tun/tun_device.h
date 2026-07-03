// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TUN_TUN_DEVICE_H
#define CLV_VPN_TUN_TUN_DEVICE_H

#include <asio.hpp>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <sys/uio.h> // struct iovec for WriteBatchRaw

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
 * Platform-specific virtual network interface for VPN tunneling.
 * Supports:
 * - Linux TUN devices (/dev/net/tun)
 * - Async I/O with ASIO
 * - IPv4 and IPv6 packets
 *
 * Usage:
 * @code
 * TunDevice tun(io_context);
 * tun.Create("tun0");
 * tun.SetAddress("10.8.0.1", 24);
 * tun.SetMtu(1500);
 * tun.BringUp();
 *
 * // Async read/write
 * auto pkt = co_await tun.ReadPacket();
 * co_await tun.WritePacket(pkt);
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
    TunDevice(TunDevice &&) noexcept;
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
     * @brief Read a batch of packets from TUN device (async)
     *
     * Waits for the TUN fd to become readable, then performs non-blocking
     * reads in a loop to drain up to @p max_batch packets without
     * re-entering epoll. This is the TUN equivalent of recvmmsg batching.
     *
     * @param max_batch Maximum number of packets to read per wake
     * @return Vector of 1..max_batch IP packets
     * @throws asio::system_error on I/O error
     */
    asio::awaitable<std::vector<IpPacket>> ReadBatch(std::size_t max_batch);

    /**
     * @brief Read a batch of packets directly into caller-provided buffers (zero-copy)
     *
     * Each element in @p slots points to a writable buffer of at least
     * @p max_payload bytes. The first read uses async_read_some (ASIO/epoll
     * integration), remaining reads are non-blocking drain.
     *
     * @param slots      Array of {pointer, capacity} pairs — one per potential packet
     * @param max_batch  Maximum packets to read (must be <= slots size)
     * @return Number of packets read. For each i in [0..N), slots[i].len is set.
     * @throws asio::system_error on I/O error
     * @note Intended for zero-copy arena paths — TUN data lands directly in
     *       the caller's memory with no intermediate copy.
     */
    struct SlotBuffer
    {
        std::uint8_t *buf;    ///< Writable destination buffer
        std::size_t capacity; ///< Available bytes in buf
        std::size_t len = 0;  ///< Output: bytes actually read
    };

    asio::awaitable<std::size_t> ReadBatchInto(std::span<SlotBuffer> slots);

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
     * @brief Batch-write multiple IP packets to TUN via writev(2)
     *
     * Collects all packet spans into a single writev() syscall for minimal
     * per-packet overhead. Synchronous (non-coroutine) — suitable for the
     * zero-copy inbound arena path where we want to avoid coroutine overhead.
     *
     * @param iovecs Array of iovec structs pointing at decrypted IP packets.
     *               Caller retains ownership of the underlying buffers.
     * @param count  Number of iovecs
     * @return Number of bytes written, or -1 on error
     * @note The TUN device accepts one IP packet per write() call. writev()
     *       with multiple iovecs concatenates them into a single packet, so
     *       this method calls write() per-iovec for correctness.
     */
    std::size_t WriteBatchRaw(const struct iovec *iovecs, std::size_t count);

    /**
     * @brief Get the native file descriptor of the TUN device
     *
     * Useful for synchronous I/O (e.g., ::write / ::writev) on the arena path.
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
     * Read buffer — shared by ReadPacket() and ReadBatch().
     * Invariant: only one coroutine reads from the TUN fd at a time.
     * If multi-queue TUN is added later, each queue needs its own buffer.
     */
    std::array<std::uint8_t, MAX_PACKET_SIZE> read_buffer_;
};

} // namespace clv::vpn::tun

#endif // CLV_VPN_TUN_TUN_DEVICE_H
