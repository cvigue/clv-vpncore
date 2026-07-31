// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "tun_device.h"

#include <arpa/inet.h>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>
#include <unique_fd.h>
#include <utility>

namespace clv::vpn::tun {

TunDevice::TunDevice(asio::io_context &io_context) : io_context_(io_context)
{
}

TunDevice::~TunDevice()
{
    Close();
}

TunDevice::TunDevice(TunDevice &&other) noexcept
    : io_context_(other.io_context_), stream_(std::move(other.stream_)), dev_name_(std::move(other.dev_name_)),
      mtu_(other.mtu_)
{
}

TunDevice &TunDevice::operator=(TunDevice &&other) noexcept
{
    if (this != &other)
    {
        Close();
        stream_ = std::move(other.stream_);
        dev_name_ = std::move(other.dev_name_);
        mtu_ = other.mtu_;
    }
    return *this;
}

std::string TunDevice::Create(const std::string &dev_name, int mode)
{
    if (IsOpen())
    {
        throw std::logic_error("TUN device already open");
    }

    // Open /dev/net/tun
    clv::UniqueFd fd(::open("/dev/net/tun", mode));

    // Configure TUN device
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));

    // IFF_TUN: TUN device (layer 3, IP packets)
    // IFF_NO_PI: No packet information header (we want raw IP packets)
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (!dev_name.empty())
    {
        if (dev_name.length() >= IFNAMSIZ)
        {
            throw std::invalid_argument("Device name too long");
        }
        std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);
    }

    // Create the device
    if (::ioctl(fd.get(), TUNSETIFF, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "TUNSETIFF ioctl failed");
    }

    // Store actual device name (kernel may have assigned one)
    dev_name_ = ifr.ifr_name;

    // ASIO takes sole ownership of the fd and will close it in stream_->close()
    stream_ = std::make_unique<asio::posix::stream_descriptor>(io_context_, fd.release());

    return dev_name_;
}

void TunDevice::SetAddress(const std::string &addr, std::uint8_t prefix_len)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    // Create socket for ioctl operations
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    // Set IP address
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);

    struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    addr_in->sin_family = AF_INET;
    if (::inet_pton(AF_INET, addr.c_str(), &addr_in->sin_addr) != 1)
    {
        throw std::invalid_argument("Invalid IP address: " + addr);
    }

    if (::ioctl(sock.get(), SIOCSIFADDR, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFADDR ioctl failed");
    }

    // Set netmask based on prefix length
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);

    struct sockaddr_in *netmask = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_netmask);
    netmask->sin_family = AF_INET;

    // Convert prefix length to netmask
    if (prefix_len > 32)
    {
        throw std::invalid_argument("Invalid prefix length: " + std::to_string(prefix_len));
    }

    std::uint32_t mask = prefix_len == 0 ? 0 : (~0u << (32 - prefix_len));
    netmask->sin_addr.s_addr = htonl(mask);

    if (::ioctl(sock.get(), SIOCSIFNETMASK, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFNETMASK ioctl failed");
    }
}

void TunDevice::AddIpv6Address(const std::string &addr, std::uint8_t prefix_len)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    if (prefix_len > 128)
    {
        throw std::invalid_argument("Invalid IPv6 prefix length: " + std::to_string(prefix_len));
    }

    // Resolve interface index
    unsigned int ifindex = ::if_nametoindex(dev_name_.c_str());
    if (ifindex == 0)
    {
        throw std::system_error(errno, std::system_category(), "if_nametoindex failed for " + dev_name_);
    }

    struct in6_ifreq ifr6;
    std::memset(&ifr6, 0, sizeof(ifr6));
    if (::inet_pton(AF_INET6, addr.c_str(), &ifr6.ifr6_addr) != 1)
    {
        throw std::invalid_argument("Invalid IPv6 address: " + addr);
    }
    ifr6.ifr6_prefixlen = prefix_len;
    ifr6.ifr6_ifindex = static_cast<int>(ifindex);

    clv::UniqueFd sock(::socket(AF_INET6, SOCK_DGRAM, 0));
    if (::ioctl(sock.get(), SIOCSIFADDR, &ifr6) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFADDR (IPv6) ioctl failed for " + addr);
    }
}

void TunDevice::SetMtu(std::uint16_t mtu)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    if (mtu > MAX_MTU)
    {
        throw std::invalid_argument("MTU exceeds maximum: " + std::to_string(mtu));
    }

    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    if (::ioctl(sock.get(), SIOCSIFMTU, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFMTU ioctl failed");
    }

    mtu_ = mtu;
}

void TunDevice::SetTxQueueLen(int len)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_qlen = len;

    if (::ioctl(sock.get(), SIOCSIFTXQLEN, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFTXQLEN ioctl failed");
    }
}

void TunDevice::BringUp()
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    // Get current flags
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);

    if (::ioctl(sock.get(), SIOCGIFFLAGS, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCGIFFLAGS ioctl failed");
    }

    // Set IFF_UP flag
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (::ioctl(sock.get(), SIOCSIFFLAGS, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFFLAGS ioctl failed");
    }
}

void TunDevice::BringDown()
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    // Get current flags
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev_name_.c_str(), IFNAMSIZ - 1);

    if (::ioctl(sock.get(), SIOCGIFFLAGS, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCGIFFLAGS ioctl failed");
    }

    // Clear IFF_UP flag
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

    if (::ioctl(sock.get(), SIOCSIFFLAGS, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "SIOCSIFFLAGS ioctl failed");
    }
}

void TunDevice::Close()
{
    if (stream_)
    {
        stream_->close();
        stream_.reset();
    }

    dev_name_.clear();
}

bool TunDevice::IsOpen() const
{
    return stream_ && stream_->is_open();
}

asio::awaitable<std::size_t> TunDevice::ReadPacketInto(std::span<std::uint8_t> dest)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }
    if (dest.empty())
    {
        throw std::invalid_argument("ReadPacketInto destination is empty");
    }

    co_return co_await stream_->async_read_some(
        asio::buffer(dest.data(), dest.size()), asio::use_awaitable);
}

std::size_t TunDevice::TryReadPacketInto(std::span<std::uint8_t> dest)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }
    if (dest.empty())
    {
        throw std::invalid_argument("TryReadPacketInto destination is empty");
    }

    // poll(0) + ::read avoids flipping the descriptor to non-blocking (which
    // would stick for the lifetime of the TunDevice and surprise other paths).
    // Caller must not have an outstanding async_read on this device.
    const int fd = stream_->native_handle();
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int pr = ::poll(&pfd, 1, 0);
    if (pr == 0)
        return 0;
    if (pr < 0)
        throw std::system_error(errno, std::generic_category(), "poll(TUN)");

    const ssize_t n = ::read(fd, dest.data(), dest.size());
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        throw std::system_error(errno, std::generic_category(), "read(TUN)");
    }
    return static_cast<std::size_t>(n);
}

asio::awaitable<IpPacket> TunDevice::ReadPacket()
{
    const std::size_t bytes_read = co_await ReadPacketInto(read_buffer_);

    IpPacket packet;
    packet.data.assign(read_buffer_.begin(), read_buffer_.begin() + bytes_read);

    co_return packet;
}

asio::awaitable<void> TunDevice::WritePacket(std::span<const std::uint8_t> data)
{
    if (!IsOpen())
    {
        throw std::logic_error("TUN device not open");
    }

    if (data.empty())
    {
        throw std::invalid_argument("Cannot write empty packet");
    }

    // No software MTU check — the kernel TUN device enforces MTU correctly.
    // Oversized packets trigger ICMP "fragmentation needed" responses which
    // propagate path MTU discovery to the sender.

    co_await asio::async_write(*stream_, asio::buffer(data.data(), data.size()), asio::use_awaitable);
}

asio::awaitable<void> TunDevice::WritePacket(const IpPacket &pkt)
{
    co_await WritePacket(std::span<const std::uint8_t>(pkt.data));
}

int TunDevice::NativeHandle() const
{
    if (!IsOpen())
        return -1;
    return stream_->native_handle();
}

} // namespace clv::vpn::tun
