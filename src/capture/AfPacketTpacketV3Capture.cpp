#include "capture/AfPacketTpacketV3Capture.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <span>
#include <sstream>
#include <utility>

#if defined(__linux__)
#include <cerrno>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pcap_constrictor_afpacket {

AfPacketTpacketV3Capture::~AfPacketTpacketV3Capture() {
    Close();
}

bool AfPacketTpacketV3Capture::Open(const PolicyConfig::CaptureOptions& config) {
    Close();
    error_message_.clear();
    non_fatal_receive_errors_ = 0;

    if (config.interface.empty()) {
        SetError("missing interface name");
        return false;
    }

#if defined(__linux__)
    if (!ValidateRingConfiguration(config)) {
        return false;
    }

    errno = 0;
    const unsigned int ifindex = if_nametoindex(config.interface.c_str());
    if (ifindex == 0U) {
        std::ostringstream out;
        out << "if_nametoindex failed for interface '" << config.interface << "'";
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

    int packet_version = TPACKET_V3;
    if (::setsockopt(socket_fd,
                     SOL_PACKET,
                     PACKET_VERSION,
                     &packet_version,
                     sizeof(packet_version)) != 0) {
        std::ostringstream out;
        out << "failed to set PACKET_VERSION to TPACKET_V3: " << std::strerror(errno);
        ::close(socket_fd);
        SetError(out.str());
        return false;
    }

    const std::uint64_t frames_per_block =
        static_cast<std::uint64_t>(config.ring_block_size) /
        static_cast<std::uint64_t>(config.ring_frame_size);
    const std::uint64_t frame_count =
        frames_per_block * static_cast<std::uint64_t>(config.ring_block_count);
    if (frame_count == 0U || frame_count > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        ::close(socket_fd);
        SetError("invalid TPACKET_V3 ring layout: frame count is out of range");
        return false;
    }

    tpacket_req3 request{};
    request.tp_block_size = config.ring_block_size;
    request.tp_block_nr = config.ring_block_count;
    request.tp_frame_size = config.ring_frame_size;
    request.tp_frame_nr = static_cast<std::uint32_t>(frame_count);
    request.tp_retire_blk_tov = config.block_timeout_ms;

    if (::setsockopt(socket_fd,
                     SOL_PACKET,
                     PACKET_RX_RING,
                     &request,
                     sizeof(request)) != 0) {
        std::ostringstream out;
        out << "failed to configure PACKET_RX_RING: " << std::strerror(errno);
        ::close(socket_fd);
        SetError(out.str());
        return false;
    }

    const std::size_t mapping_size =
        static_cast<std::size_t>(config.ring_block_size) *
        static_cast<std::size_t>(config.ring_block_count);
    void* mapped = ::mmap(nullptr,
                          mapping_size,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED,
                          socket_fd,
                          0);
    if (mapped == MAP_FAILED) {
        std::ostringstream out;
        out << "failed to mmap PACKET_RX_RING: " << std::strerror(errno);
        tpacket_req3 empty_request{};
        (void)::setsockopt(socket_fd, SOL_PACKET, PACKET_RX_RING, &empty_request, sizeof(empty_request));
        ::close(socket_fd);
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
        out << "failed to bind AF_PACKET socket to interface '" << config.interface
            << "': " << std::strerror(errno);
        tpacket_req3 empty_request{};
        (void)::setsockopt(socket_fd, SOL_PACKET, PACKET_RX_RING, &empty_request, sizeof(empty_request));
        ::munmap(mapped, mapping_size);
        ::close(socket_fd);
        SetError(out.str());
        return false;
    }

    socket_fd_ = socket_fd;
    ring_mapping_ = static_cast<std::byte*>(mapped);
    ring_mapping_size_ = mapping_size;
    block_size_ = config.ring_block_size;
    block_count_ = config.ring_block_count;
    poll_timeout_ms_ = std::max(config.block_timeout_ms, 1U);
    interface_index_ = static_cast<std::uint32_t>(ifindex);
    current_block_index_ = 0;
    current_block_packet_index_ = 0;
    current_block_packet_count_ = 0;
    current_packet_offset_ = 0;
    current_block_active_ = false;
    return true;
#else
    (void)config;
    SetError("TPACKET_V3 live capture is only supported on Linux");
    return false;
#endif
}

AfPacketReceiveStatus AfPacketTpacketV3Capture::ReceiveNext(
    CapturedPacket& packet,
    const volatile std::sig_atomic_t* stop_requested) {
#if defined(__linux__)
    if (socket_fd_ < 0 || ring_mapping_ == nullptr) {
        SetError("TPACKET_V3 capture is not open");
        return AfPacketReceiveStatus::Error;
    }

    error_message_.clear();

    for (;;) {
        if (stop_requested != nullptr && *stop_requested != 0) {
            return AfPacketReceiveStatus::Interrupted;
        }

        if (current_block_active_) {
            if (current_block_packet_index_ >= current_block_packet_count_) {
                ReleaseCurrentBlock();
                continue;
            }

            const std::byte* block_base = current_block_base();
            if (block_base == nullptr) {
                SetError("invalid current TPACKET_V3 block");
                return AfPacketReceiveStatus::Error;
            }

            const std::size_t packet_offset = current_packet_offset_;
            if (packet_offset + sizeof(tpacket3_hdr) > block_size_) {
                SetError("invalid TPACKET_V3 packet header offset");
                return AfPacketReceiveStatus::Error;
            }

            const auto* packet_header =
                reinterpret_cast<const tpacket3_hdr*>(block_base + packet_offset);

            const std::size_t packet_data_offset = packet_offset + packet_header->tp_mac;
            const std::size_t packet_data_end =
                packet_data_offset + static_cast<std::size_t>(packet_header->tp_snaplen);
            if (packet_data_offset > block_size_ || packet_data_end > block_size_) {
                SetError("invalid TPACKET_V3 packet data bounds");
                return AfPacketReceiveStatus::Error;
            }

            if (packet_header->tp_snaplen > packet_header->tp_len) {
                SetError("invalid TPACKET_V3 packet lengths");
                return AfPacketReceiveStatus::Error;
            }

            PacketDirection direction = PacketDirection::Unknown;
            std::uint32_t packet_ifindex = interface_index_;
            const std::size_t sockaddr_offset =
                packet_offset + TPACKET_ALIGN(sizeof(tpacket3_hdr));
            if (sockaddr_offset + sizeof(sockaddr_ll) <= block_size_ &&
                packet_header->tp_mac >= TPACKET_ALIGN(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll)) {
                const auto* packet_address =
                    reinterpret_cast<const sockaddr_ll*>(block_base + sockaddr_offset);
                direction = AfPacketCapture::MapPacketTypeToDirection(packet_address->sll_pkttype);
                if (packet_address->sll_ifindex > 0) {
                    packet_ifindex = static_cast<std::uint32_t>(packet_address->sll_ifindex);
                }
            }

            const auto packet_time =
                std::chrono::system_clock::time_point(std::chrono::seconds(packet_header->tp_sec) +
                                                      std::chrono::nanoseconds(packet_header->tp_nsec));

            packet = CapturedPacket{
                .packet = PacketView(
                    std::span<const std::byte>(block_base + packet_data_offset,
                                               static_cast<std::size_t>(packet_header->tp_snaplen)),
                    packet_header->tp_snaplen,
                    packet_header->tp_len),
                .timestamp = packet_time,
                .ifindex = packet_ifindex,
                .direction = direction,
            };

            ++current_block_packet_index_;
            if (current_block_packet_index_ < current_block_packet_count_) {
                if (packet_header->tp_next_offset == 0U) {
                    SetError("invalid TPACKET_V3 packet chain");
                    return AfPacketReceiveStatus::Error;
                }

                current_packet_offset_ += packet_header->tp_next_offset;
            }

            return AfPacketReceiveStatus::Packet;
        }

        AfPacketReceiveStatus wait_status = AfPacketReceiveStatus::Timeout;
        if (!WaitForReadyBlock(stop_requested, wait_status)) {
            return wait_status;
        }

        if (!ActivateCurrentBlock()) {
            if (!error_message_.empty()) {
                return AfPacketReceiveStatus::Error;
            }
            continue;
        }
    }
#else
    (void)packet;
    (void)stop_requested;
    SetError("TPACKET_V3 live capture is only supported on Linux");
    return AfPacketReceiveStatus::Error;
#endif
}

bool AfPacketTpacketV3Capture::is_open() const noexcept {
#if defined(__linux__)
    return socket_fd_ >= 0 && ring_mapping_ != nullptr;
#else
    return false;
#endif
}

const std::string& AfPacketTpacketV3Capture::error_message() const noexcept {
    return error_message_;
}

std::uint64_t AfPacketTpacketV3Capture::non_fatal_receive_errors() const noexcept {
    return non_fatal_receive_errors_;
}

bool AfPacketTpacketV3Capture::TryReadKernelStats(AfPacketKernelStats& stats) const noexcept {
#if defined(__linux__)
    if (socket_fd_ < 0) {
        return false;
    }

    tpacket_stats_v3 native_stats{};
    socklen_t option_length = sizeof(native_stats);
    if (::getsockopt(socket_fd_,
                     SOL_PACKET,
                     PACKET_STATISTICS,
                     &native_stats,
                     &option_length) != 0) {
        return false;
    }

    stats = AfPacketKernelStats{
        .packets = native_stats.tp_packets,
        .drops = native_stats.tp_drops,
    };
    return true;
#else
    (void)stats;
    return false;
#endif
}

void AfPacketTpacketV3Capture::Close() noexcept {
#if defined(__linux__)
    current_block_active_ = false;
    current_block_index_ = 0;
    current_block_packet_index_ = 0;
    current_block_packet_count_ = 0;
    current_packet_offset_ = 0;

    if (socket_fd_ >= 0) {
        tpacket_req3 empty_request{};
        (void)::setsockopt(socket_fd_, SOL_PACKET, PACKET_RX_RING, &empty_request, sizeof(empty_request));
    }

    if (ring_mapping_ != nullptr) {
        ::munmap(ring_mapping_, ring_mapping_size_);
        ring_mapping_ = nullptr;
        ring_mapping_size_ = 0;
    }

    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }

    block_size_ = 0;
    block_count_ = 0;
    poll_timeout_ms_ = 1000;
#endif
    interface_index_ = 0;
    non_fatal_receive_errors_ = 0;
}

void AfPacketTpacketV3Capture::SetError(std::string message) {
    error_message_ = std::move(message);
}

#if defined(__linux__)
bool AfPacketTpacketV3Capture::ValidateRingConfiguration(const PolicyConfig::CaptureOptions& config) {
    if (config.ring_block_size == 0U) {
        SetError("capture.ring_block_size must be greater than 0");
        return false;
    }
    if (config.ring_block_count == 0U) {
        SetError("capture.ring_block_count must be greater than 0");
        return false;
    }
    if (config.ring_frame_size == 0U) {
        SetError("capture.ring_frame_size must be greater than 0");
        return false;
    }
    if (config.ring_block_size % config.ring_frame_size != 0U) {
        SetError("capture.ring_block_size must be a multiple of capture.ring_frame_size");
        return false;
    }

    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size > 0 && config.ring_block_size % static_cast<std::uint32_t>(page_size) != 0U) {
        SetError("capture.ring_block_size must be aligned to the system page size");
        return false;
    }

    if (config.ring_frame_size % TPACKET_ALIGNMENT != 0U) {
        SetError("capture.ring_frame_size must be aligned to TPACKET_ALIGNMENT");
        return false;
    }

    const std::size_t minimum_frame_size =
        TPACKET_ALIGN(sizeof(tpacket3_hdr)) + TPACKET_ALIGN(sizeof(sockaddr_ll));
    if (config.ring_frame_size < minimum_frame_size) {
        SetError("capture.ring_frame_size is too small for TPACKET_V3 metadata");
        return false;
    }

    return true;
}

bool AfPacketTpacketV3Capture::WaitForReadyBlock(
    const volatile std::sig_atomic_t* stop_requested,
    AfPacketReceiveStatus& status) {
    for (;;) {
        const std::byte* block_base = current_block_base();
        if (block_base == nullptr) {
            SetError("invalid TPACKET_V3 block pointer");
            status = AfPacketReceiveStatus::Error;
            return false;
        }

        const auto* block_desc = reinterpret_cast<const tpacket_block_desc*>(block_base);
        __sync_synchronize();
        if ((block_desc->hdr.bh1.block_status & TP_STATUS_USER) != 0U) {
            return true;
        }

        pollfd poll_descriptor{};
        poll_descriptor.fd = socket_fd_;
        poll_descriptor.events = POLLIN | POLLERR;

        const int poll_result =
            ::poll(&poll_descriptor, 1, static_cast<int>(poll_timeout_ms_));
        if (poll_result < 0) {
            if (errno == EINTR) {
                if (stop_requested != nullptr && *stop_requested != 0) {
                    status = AfPacketReceiveStatus::Interrupted;
                    return false;
                }
                continue;
            }

            ++non_fatal_receive_errors_;
            std::ostringstream out;
            out << "failed to poll TPACKET_V3 socket: " << std::strerror(errno);
            SetError(out.str());
            status = AfPacketReceiveStatus::Error;
            return false;
        }

        if (poll_result == 0) {
            if (stop_requested != nullptr && *stop_requested != 0) {
                status = AfPacketReceiveStatus::Interrupted;
                return false;
            }
            status = AfPacketReceiveStatus::Timeout;
            return false;
        }

        if ((poll_descriptor.revents & (POLLERR | POLLNVAL | POLLHUP)) != 0) {
            ++non_fatal_receive_errors_;
            SetError("TPACKET_V3 poll reported a socket error");
            status = AfPacketReceiveStatus::Error;
            return false;
        }
    }
}

bool AfPacketTpacketV3Capture::ActivateCurrentBlock() {
    error_message_.clear();

    const std::byte* block_base = current_block_base();
    if (block_base == nullptr) {
        SetError("invalid TPACKET_V3 block pointer");
        return false;
    }

    const auto* block_desc = reinterpret_cast<const tpacket_block_desc*>(block_base);
    if ((block_desc->hdr.bh1.block_status & TP_STATUS_USER) == 0U) {
        return false;
    }

    if (block_desc->hdr.bh1.num_pkts == 0U) {
        ReleaseCurrentBlock();
        return false;
    }

    if (block_desc->hdr.bh1.offset_to_first_pkt >= block_size_) {
        SetError("invalid TPACKET_V3 first packet offset");
        return false;
    }

    current_block_packet_index_ = 0;
    current_block_packet_count_ = block_desc->hdr.bh1.num_pkts;
    current_packet_offset_ = block_desc->hdr.bh1.offset_to_first_pkt;
    current_block_active_ = true;
    return true;
}

const std::byte* AfPacketTpacketV3Capture::current_block_base() const noexcept {
    if (ring_mapping_ == nullptr || block_count_ == 0U) {
        return nullptr;
    }

    return ring_mapping_ + (static_cast<std::size_t>(current_block_index_) * block_size_);
}

void AfPacketTpacketV3Capture::ReleaseCurrentBlock() noexcept {
    if (!current_block_active_ && ring_mapping_ == nullptr) {
        return;
    }

    std::byte* block_base =
        ring_mapping_ + (static_cast<std::size_t>(current_block_index_) * block_size_);
    auto* block_desc = reinterpret_cast<tpacket_block_desc*>(block_base);
    __sync_synchronize();
    block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;

    current_block_active_ = false;
    current_block_packet_index_ = 0;
    current_block_packet_count_ = 0;
    current_packet_offset_ = 0;
    current_block_index_ = (current_block_index_ + 1U) % block_count_;
}
#endif

}  // namespace pcap_constrictor_afpacket
