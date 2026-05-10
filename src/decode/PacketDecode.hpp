#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace pcap_constrictor_afpacket {

enum class IpVersion {
    None,
    Ipv4,
    Ipv6,
};

enum class TransportProtocol {
    None,
    Tcp,
    Udp,
};

enum class PacketDecodeFailureReason {
    None,
    TruncatedEthernetHeader,
    TruncatedVlanTag,
    TruncatedIpv4Header,
    InvalidIpv4Ihl,
    InvalidIpv4TotalLength,
    TruncatedIpv4Packet,
    TruncatedIpv6Header,
    TruncatedIpv6Packet,
    UnsupportedIpv6ExtensionHeaders,
    TruncatedTcpHeader,
    InvalidTcpDataOffset,
    TruncatedUdpHeader,
    InvalidUdpLength,
    TruncatedUdpPayload,
};

struct PacketDecodeResult {
    bool success{false};
    PacketDecodeFailureReason failure_reason{PacketDecodeFailureReason::None};

    std::uint16_t ethertype{0};
    std::uint8_t vlan_tag_count{0};
    IpVersion ip_version{IpVersion::None};
    TransportProtocol transport_protocol{TransportProtocol::None};
    std::uint8_t ip_protocol{0};

    std::size_t link_header_length{0};
    std::size_t network_header_offset{0};
    std::size_t network_header_length{0};
    std::size_t transport_header_offset{0};
    std::size_t transport_header_length{0};
    std::size_t transport_payload_offset{0};
    std::size_t transport_payload_length{0};

    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint32_t tcp_seq{0};

    std::array<std::byte, 16> src_address{};
    std::array<std::byte, 16> dst_address{};
    std::uint8_t address_length{0};

    [[nodiscard]] bool parsed_ip() const noexcept {
        return success && ip_version != IpVersion::None;
    }

    [[nodiscard]] bool parsed_transport() const noexcept {
        return success && transport_protocol != TransportProtocol::None;
    }

    [[nodiscard]] bool is_non_ip() const noexcept {
        return success && ip_version == IpVersion::None;
    }

    [[nodiscard]] std::string_view failure_reason_string() const noexcept;
};

[[nodiscard]] PacketDecodeResult DecodePacket(std::span<const std::byte> packet) noexcept;

}  // namespace pcap_constrictor_afpacket
