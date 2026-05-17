#include "decode/PacketDecode.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace pcap_constrictor_afpacket {

namespace {

constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeProviderBridge = 0x88A8U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;

constexpr std::uint8_t kIpProtocolTcp = 6U;
constexpr std::uint8_t kIpProtocolUdp = 17U;

constexpr std::uint8_t kIpv6HopByHop = 0U;
constexpr std::uint8_t kIpv6Routing = 43U;
constexpr std::uint8_t kIpv6Fragment = 44U;
constexpr std::uint8_t kIpv6Authentication = 51U;
constexpr std::uint8_t kIpv6DestinationOptions = 60U;
constexpr std::uint8_t kIpv6Mobility = 135U;
constexpr std::uint8_t kIpv6Hip = 139U;
constexpr std::uint8_t kIpv6Shim6 = 140U;

bool HasBytes(const std::span<const std::byte> packet,
              const std::size_t offset,
              const std::size_t count) noexcept {
    return offset <= packet.size() && count <= packet.size() - offset;
}

std::uint16_t ReadBe16(const std::span<const std::byte> packet,
                       const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(packet[offset])) << 8U |
           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(packet[offset + 1U]));
}

bool IsVlanEthertype(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan || ether_type == kEtherTypeProviderBridge;
}

bool IsUnsupportedIpv6Extension(const std::uint8_t next_header) noexcept {
    return next_header == kIpv6HopByHop ||
           next_header == kIpv6Routing ||
           next_header == kIpv6Fragment ||
           next_header == kIpv6Authentication ||
           next_header == kIpv6DestinationOptions ||
           next_header == kIpv6Mobility ||
           next_header == kIpv6Hip ||
           next_header == kIpv6Shim6;
}

void CopyAddress(std::array<std::byte, 16>& destination,
                 const std::span<const std::byte> packet,
                 const std::size_t offset,
                 const std::size_t length) noexcept {
    destination.fill(std::byte{0});
    std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                static_cast<std::ptrdiff_t>(length),
                destination.begin());
}

void DecodeTcp(PacketDecodeResult& result,
               const std::span<const std::byte> packet,
               const std::size_t transport_offset,
               const std::size_t transport_end) noexcept {
    if (!HasBytes(packet, transport_offset, 20U) || transport_offset + 20U > transport_end) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedTcpHeader;
        result.success = false;
        return;
    }

    const auto header_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet[transport_offset + 12U]) >> 4U) * 4U);
    if (header_length < 20U) {
        result.failure_reason = PacketDecodeFailureReason::InvalidTcpDataOffset;
        result.success = false;
        return;
    }

    if (!HasBytes(packet, transport_offset, header_length) ||
        transport_offset + header_length > transport_end) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedTcpHeader;
        result.success = false;
        return;
    }

    result.transport_protocol = TransportProtocol::Tcp;
    result.transport_header_offset = transport_offset;
    result.transport_header_length = header_length;
    result.transport_payload_offset = transport_offset + header_length;
    result.transport_payload_length = transport_end - result.transport_payload_offset;
    result.src_port = ReadBe16(packet, transport_offset);
    result.dst_port = ReadBe16(packet, transport_offset + 2U);
    result.tcp_seq =
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(packet[transport_offset + 4U])) << 24U |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(packet[transport_offset + 5U])) << 16U |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(packet[transport_offset + 6U])) << 8U |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(packet[transport_offset + 7U]));
    result.tcp_flags = std::to_integer<std::uint8_t>(packet[transport_offset + 13U]);
}

void DecodeUdp(PacketDecodeResult& result,
               const std::span<const std::byte> packet,
               const std::size_t transport_offset,
               const std::size_t transport_end) noexcept {
    if (!HasBytes(packet, transport_offset, 8U) || transport_offset + 8U > transport_end) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedUdpHeader;
        result.success = false;
        return;
    }

    const std::uint16_t udp_length = ReadBe16(packet, transport_offset + 4U);
    if (udp_length < 8U) {
        result.failure_reason = PacketDecodeFailureReason::InvalidUdpLength;
        result.success = false;
        return;
    }

    if (transport_offset + static_cast<std::size_t>(udp_length) > transport_end) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedUdpPayload;
        result.success = false;
        return;
    }

    result.transport_protocol = TransportProtocol::Udp;
    result.transport_header_offset = transport_offset;
    result.transport_header_length = 8U;
    result.transport_payload_offset = transport_offset + 8U;
    result.transport_payload_length = static_cast<std::size_t>(udp_length) - 8U;
    result.src_port = ReadBe16(packet, transport_offset);
    result.dst_port = ReadBe16(packet, transport_offset + 2U);
}

void DecodeIpv4(PacketDecodeResult& result,
                const std::span<const std::byte> packet,
                const std::size_t network_offset) noexcept {
    if (!HasBytes(packet, network_offset, 20U)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv4Header;
        result.success = false;
        return;
    }

    const auto version = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(packet[network_offset]) >> 4U);
    const auto ihl =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet[network_offset]) & 0x0FU) * 4U);
    if (version != 4U || ihl < 20U) {
        result.failure_reason = PacketDecodeFailureReason::InvalidIpv4Ihl;
        result.success = false;
        return;
    }

    if (!HasBytes(packet, network_offset, ihl)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv4Header;
        result.success = false;
        return;
    }

    const auto total_length = ReadBe16(packet, network_offset + 2U);
    if (total_length < ihl) {
        result.failure_reason = PacketDecodeFailureReason::InvalidIpv4TotalLength;
        result.success = false;
        return;
    }

    if (!HasBytes(packet, network_offset, total_length)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv4Packet;
        result.success = false;
        return;
    }

    result.success = true;
    result.ip_version = IpVersion::Ipv4;
    result.network_header_offset = network_offset;
    result.network_header_length = ihl;
    result.ip_protocol = std::to_integer<std::uint8_t>(packet[network_offset + 9U]);
    result.address_length = 4U;
    CopyAddress(result.src_address, packet, network_offset + 12U, 4U);
    CopyAddress(result.dst_address, packet, network_offset + 16U, 4U);

    const auto flags_fragment = ReadBe16(packet, network_offset + 6U);
    const bool more_fragments = (flags_fragment & 0x2000U) != 0U;
    const auto fragment_offset = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
    if (more_fragments || fragment_offset != 0U) {
        return;
    }

    const auto transport_offset = network_offset + ihl;
    const auto transport_end = network_offset + static_cast<std::size_t>(total_length);
    if (result.ip_protocol == kIpProtocolTcp) {
        DecodeTcp(result, packet, transport_offset, transport_end);
    } else if (result.ip_protocol == kIpProtocolUdp) {
        DecodeUdp(result, packet, transport_offset, transport_end);
    }
}

void DecodeIpv6(PacketDecodeResult& result,
                const std::span<const std::byte> packet,
                const std::size_t network_offset) noexcept {
    if (!HasBytes(packet, network_offset, 40U)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv6Header;
        result.success = false;
        return;
    }

    const auto version = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(packet[network_offset]) >> 4U);
    if (version != 6U) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv6Header;
        result.success = false;
        return;
    }

    const auto payload_length = ReadBe16(packet, network_offset + 4U);
    const auto total_length = 40U + static_cast<std::size_t>(payload_length);
    if (!HasBytes(packet, network_offset, total_length)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedIpv6Packet;
        result.success = false;
        return;
    }

    result.success = true;
    result.ip_version = IpVersion::Ipv6;
    result.network_header_offset = network_offset;
    result.network_header_length = 40U;
    result.ip_protocol = std::to_integer<std::uint8_t>(packet[network_offset + 6U]);
    result.address_length = 16U;
    CopyAddress(result.src_address, packet, network_offset + 8U, 16U);
    CopyAddress(result.dst_address, packet, network_offset + 24U, 16U);

    if (IsUnsupportedIpv6Extension(result.ip_protocol)) {
        result.failure_reason = PacketDecodeFailureReason::UnsupportedIpv6ExtensionHeaders;
        result.success = false;
        return;
    }

    const auto transport_offset = network_offset + 40U;
    const auto transport_end = network_offset + total_length;
    if (result.ip_protocol == kIpProtocolTcp) {
        DecodeTcp(result, packet, transport_offset, transport_end);
    } else if (result.ip_protocol == kIpProtocolUdp) {
        DecodeUdp(result, packet, transport_offset, transport_end);
    }
}

}  // namespace

std::string_view PacketDecodeResult::failure_reason_string() const noexcept {
    switch (failure_reason) {
        case PacketDecodeFailureReason::None:
            return "none";
        case PacketDecodeFailureReason::TruncatedEthernetHeader:
            return "truncated_ethernet_header";
        case PacketDecodeFailureReason::TruncatedVlanTag:
            return "truncated_vlan_tag";
        case PacketDecodeFailureReason::TruncatedIpv4Header:
            return "truncated_ipv4_header";
        case PacketDecodeFailureReason::InvalidIpv4Ihl:
            return "invalid_ipv4_ihl";
        case PacketDecodeFailureReason::InvalidIpv4TotalLength:
            return "invalid_ipv4_total_length";
        case PacketDecodeFailureReason::TruncatedIpv4Packet:
            return "truncated_ipv4_packet";
        case PacketDecodeFailureReason::TruncatedIpv6Header:
            return "truncated_ipv6_header";
        case PacketDecodeFailureReason::TruncatedIpv6Packet:
            return "truncated_ipv6_packet";
        case PacketDecodeFailureReason::UnsupportedIpv6ExtensionHeaders:
            return "unsupported_ipv6_extension_headers";
        case PacketDecodeFailureReason::TruncatedTcpHeader:
            return "truncated_tcp_header";
        case PacketDecodeFailureReason::InvalidTcpDataOffset:
            return "invalid_tcp_data_offset";
        case PacketDecodeFailureReason::TruncatedUdpHeader:
            return "truncated_udp_header";
        case PacketDecodeFailureReason::InvalidUdpLength:
            return "invalid_udp_length";
        case PacketDecodeFailureReason::TruncatedUdpPayload:
            return "truncated_udp_payload";
    }

    return "unknown";
}

PacketDecodeResult DecodePacket(const std::span<const std::byte> packet) noexcept {
    PacketDecodeResult result;

    if (!HasBytes(packet, 0U, 14U)) {
        result.failure_reason = PacketDecodeFailureReason::TruncatedEthernetHeader;
        return result;
    }

    result.success = true;
    result.link_header_length = 14U;
    result.ethertype = ReadBe16(packet, 12U);

    std::size_t network_offset = 14U;
    while (IsVlanEthertype(result.ethertype)) {
        if (!HasBytes(packet, network_offset, 4U)) {
            result.success = false;
            result.failure_reason = PacketDecodeFailureReason::TruncatedVlanTag;
            return result;
        }

        ++result.vlan_tag_count;
        result.ethertype = ReadBe16(packet, network_offset + 2U);
        network_offset += 4U;
        result.link_header_length += 4U;
    }

    if (result.ethertype == kEtherTypeIpv4) {
        DecodeIpv4(result, packet, network_offset);
        return result;
    }

    if (result.ethertype == kEtherTypeIpv6) {
        DecodeIpv6(result, packet, network_offset);
        return result;
    }

    return result;
}

}  // namespace pcap_constrictor_afpacket
