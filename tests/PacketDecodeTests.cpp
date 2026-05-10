#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>

#include "decode/PacketDecode.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[PacketDecodeTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunPacketDecodeTests() {
    using namespace pcap_constrictor_afpacket;

    {
        constexpr std::array<std::byte, 54> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}, std::byte{0x12}, std::byte{0x34},
            std::byte{0x40}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x01},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x50}, std::byte{0x18}, std::byte{0x20}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        };

        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (!decoded.success || decoded.failure_reason != PacketDecodeFailureReason::None) {
            return Fail("valid IPv4 TCP packet should decode");
        }
        if (decoded.ethertype != 0x0800U || decoded.ip_version != IpVersion::Ipv4 ||
            decoded.transport_protocol != TransportProtocol::Tcp) {
            return Fail("IPv4 TCP metadata mismatch");
        }
        if (decoded.src_port != 12345U || decoded.dst_port != 443U ||
            decoded.transport_payload_offset != 54U || decoded.transport_payload_length != 0U) {
            return Fail("IPv4 TCP ports or payload offsets mismatch");
        }
    }

    {
        constexpr std::array<std::byte, 46> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x11}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x15}, std::byte{0xb3}, std::byte{0x00}, std::byte{0x35},
            std::byte{0x00}, std::byte{0x0c}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef},
        };

        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (!decoded.success || decoded.transport_protocol != TransportProtocol::Udp) {
            return Fail("valid IPv4 UDP packet should decode");
        }
        if (decoded.src_port != 5555U || decoded.dst_port != 53U ||
            decoded.transport_payload_length != 4U) {
            return Fail("IPv4 UDP ports or payload length mismatch");
        }
    }

    {
        constexpr std::array<std::byte, 74> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x86}, std::byte{0xdd},
            std::byte{0x60}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x14}, std::byte{0x06}, std::byte{0x40},
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x13}, std::byte{0x88}, std::byte{0x00}, std::byte{0x50},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x03},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x50}, std::byte{0x10}, std::byte{0x20}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        };

        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (!decoded.success || decoded.ip_version != IpVersion::Ipv6 ||
            decoded.transport_protocol != TransportProtocol::Tcp) {
            return Fail("valid IPv6 TCP packet should decode");
        }
        if (decoded.src_port != 5000U || decoded.dst_port != 80U ||
            decoded.address_length != 16U) {
            return Fail("IPv6 TCP metadata mismatch");
        }
    }

    {
        constexpr std::array<std::byte, 50> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x81}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x64}, std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x11}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x00}, std::byte{0x01},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x00}, std::byte{0x35}, std::byte{0x15}, std::byte{0xb3},
            std::byte{0x00}, std::byte{0x0c}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe},
        };

        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (!decoded.success || decoded.vlan_tag_count != 1U ||
            decoded.transport_protocol != TransportProtocol::Udp) {
            return Fail("VLAN IPv4 UDP packet should decode");
        }
        if (decoded.link_header_length != 18U) {
            return Fail("VLAN link header length mismatch");
        }
    }

    {
        constexpr std::array<std::byte, 10> packet{};
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (decoded.failure_reason != PacketDecodeFailureReason::TruncatedEthernetHeader) {
            return Fail("truncated Ethernet should fail clearly");
        }
    }

    {
        constexpr std::array<std::byte, 30> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}, std::byte{0x12}, std::byte{0x34},
            std::byte{0x40}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x01},
        };
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (decoded.failure_reason != PacketDecodeFailureReason::TruncatedIpv4Header) {
            return Fail("truncated IPv4 header should fail clearly");
        }
    }

    {
        constexpr std::array<std::byte, 34> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x44}, std::byte{0x00}, std::byte{0x00}, std::byte{0x14}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x01},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x02},
        };
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (decoded.failure_reason != PacketDecodeFailureReason::InvalidIpv4Ihl) {
            return Fail("invalid IPv4 IHL should fail clearly");
        }
    }

    {
        constexpr std::array<std::byte, 42> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x1c}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x01},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        };
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (decoded.failure_reason != PacketDecodeFailureReason::TruncatedTcpHeader) {
            return Fail("truncated TCP header should fail clearly");
        }
    }

    {
        constexpr std::array<std::byte, 40> packet{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x1a}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x11}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x01},
            std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x15}, std::byte{0xb3}, std::byte{0x00}, std::byte{0x35}, std::byte{0x00}, std::byte{0x0c},
        };
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        if (decoded.failure_reason != PacketDecodeFailureReason::TruncatedUdpHeader) {
            return Fail("truncated UDP header should fail clearly");
        }
    }

    return 0;
}
