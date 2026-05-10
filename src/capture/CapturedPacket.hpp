#pragma once

#include <chrono>
#include <cstdint>
#include <span>

#include "capture/PacketView.hpp"

namespace pcap_constrictor_afpacket {

enum class PacketDirection {
    Unknown,
    Incoming,
    Outgoing,
    Broadcast,
    Multicast,
    OtherHost,
};

struct CapturedPacket {
    PacketView packet{};
    std::chrono::system_clock::time_point timestamp{};
    std::uint32_t ifindex{0};
    PacketDirection direction{PacketDirection::Unknown};

    [[nodiscard]] std::span<const std::byte> data() const noexcept {
        return packet.data();
    }

    [[nodiscard]] std::uint32_t captured_len() const noexcept {
        return packet.captured_len();
    }

    [[nodiscard]] std::uint32_t original_len() const noexcept {
        return packet.original_len();
    }
};

}  // namespace pcap_constrictor_afpacket
