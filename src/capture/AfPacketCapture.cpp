#include "capture/AfPacketCapture.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include <utility>

#if defined(__linux__)
#include <cerrno>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace pcap_constrictor_afpacket {

AfPacketCapture::AfPacketCapture(const std::uint32_t buffer_size)
    : buffer_(std::max<std::uint32_t>(buffer_size, 65535U)) {}

AfPacketCapture::~AfPacketCapture() {
    Close();
}

bool AfPacketCapture::Open(const std::string_view interface_name) {
    Close();
    error_message_.clear();

    if (interface_name.empty()) {
        SetError("missing interface name");
        return false;
    }

#if defined(__linux__)
    errno = 0;
    const unsigned int ifindex = if_nametoindex(std::string(interface_name).c_str());
    if (ifindex == 0U) {
        std::ostringstream out;
        out << "if_nametoindex failed for interface '" << interface_name << "'";
        if (errno != 0) {
            out << ": " << std::strerror(errno);
        }
        SetError(out.str());
        return false;
    }

    const int socket_fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd < 0) {
        std::ostringstream out;
        out << "failed to create AF_PACKET socket: " << std::strerror(errno);
        SetError(out.str());
        return false;
    }

    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(ifindex);

    if (::bind(socket_fd,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != 0) {
        std::ostringstream out;
        out << "failed to bind AF_PACKET socket to interface '" << interface_name
            << "': " << std::strerror(errno);
        ::close(socket_fd);
        SetError(out.str());
        return false;
    }

    socket_fd_ = socket_fd;
    interface_index_ = static_cast<std::uint32_t>(ifindex);
    return true;
#else
    (void)interface_name;
    SetError("AF_PACKET live capture is only supported on Linux");
    return false;
#endif
}

AfPacketReceiveStatus AfPacketCapture::ReceiveNext(
    CapturedPacket& packet,
    const volatile std::sig_atomic_t* stop_requested) {
#if defined(__linux__)
    if (socket_fd_ < 0) {
        SetError("AF_PACKET socket is not open");
        return AfPacketReceiveStatus::Error;
    }

    error_message_.clear();

    for (;;) {
        sockaddr_ll address{};
        socklen_t address_length = sizeof(address);

        const ssize_t received = ::recvfrom(
            socket_fd_,
            buffer_.data(),
            buffer_.size(),
            0,
            reinterpret_cast<sockaddr*>(&address),
            &address_length);

        if (received < 0) {
            if (errno == EINTR) {
                if (stop_requested != nullptr && *stop_requested != 0) {
                    return AfPacketReceiveStatus::Interrupted;
                }
                continue;
            }

            std::ostringstream out;
            out << "failed to receive packet: " << std::strerror(errno);
            SetError(out.str());
            return AfPacketReceiveStatus::Error;
        }

        const std::uint32_t received_length = static_cast<std::uint32_t>(received);
        packet = CapturedPacket{
            .packet = PacketView(std::span<const std::byte>(buffer_.data(),
                                                            static_cast<std::size_t>(received_length)),
                                 received_length,
                                 received_length),
            .timestamp = std::chrono::system_clock::now(),
            .ifindex = address.sll_ifindex > 0
                           ? static_cast<std::uint32_t>(address.sll_ifindex)
                           : interface_index_,
            .direction = MapPacketTypeToDirection(address.sll_pkttype),
        };

        return AfPacketReceiveStatus::Packet;
    }
#else
    (void)packet;
    (void)stop_requested;
    SetError("AF_PACKET live capture is only supported on Linux");
    return AfPacketReceiveStatus::Error;
#endif
}

bool AfPacketCapture::is_open() const noexcept {
#if defined(__linux__)
    return socket_fd_ >= 0;
#else
    return false;
#endif
}

const std::string& AfPacketCapture::error_message() const noexcept {
    return error_message_;
}

PacketDirection AfPacketCapture::MapPacketTypeToDirection(const unsigned int packet_type) noexcept {
    switch (packet_type) {
        case kAfPacketTypeOutgoing:
            return PacketDirection::Outgoing;
        case kAfPacketTypeHost:
            return PacketDirection::Incoming;
        case kAfPacketTypeBroadcast:
            return PacketDirection::Broadcast;
        case kAfPacketTypeMulticast:
            return PacketDirection::Multicast;
        case kAfPacketTypeOtherHost:
            return PacketDirection::OtherHost;
        default:
            return PacketDirection::Unknown;
    }
}

void AfPacketCapture::Close() noexcept {
#if defined(__linux__)
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
#endif
    interface_index_ = 0;
}

void AfPacketCapture::SetError(std::string message) {
    error_message_ = std::move(message);
}

}  // namespace pcap_constrictor_afpacket
