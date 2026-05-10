#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "decode/PacketDecode.hpp"
#include "policy/PolicyConfig.hpp"
#include "policy/QuicConstrictor.hpp"

namespace {

constexpr std::size_t kIpv4UdpPayloadOffset = 42U;

int Fail(std::string_view message) {
    std::cerr << "[QuicConstrictorTests] " << message << '\n';
    return 1;
}

std::vector<std::byte> BuildIpv4UdpPacket(const std::vector<std::byte>& payload,
                                          const std::uint16_t src_port = 5555U,
                                          const std::uint16_t dst_port = 443U,
                                          const std::uint8_t src_ip_last = 1U,
                                          const std::uint8_t dst_ip_last = 2U) {
    const std::size_t total_size = 14U + 20U + 8U + payload.size();
    const std::uint16_t ipv4_total_length = static_cast<std::uint16_t>(20U + 8U + payload.size());
    const std::uint16_t udp_total_length = static_cast<std::uint16_t>(8U + payload.size());

    std::vector<std::byte> packet(total_size, std::byte{0});
    packet[12] = std::byte{0x08};
    packet[13] = std::byte{0x00};

    packet[14] = std::byte{0x45};
    packet[16] = static_cast<std::byte>((ipv4_total_length >> 8U) & 0xFFU);
    packet[17] = static_cast<std::byte>(ipv4_total_length & 0xFFU);
    packet[22] = std::byte{0x40};
    packet[23] = std::byte{0x11};
    packet[26] = std::byte{0x0a};
    packet[29] = static_cast<std::byte>(src_ip_last);
    packet[30] = std::byte{0x0a};
    packet[33] = static_cast<std::byte>(dst_ip_last);

    packet[34] = static_cast<std::byte>((src_port >> 8U) & 0xFFU);
    packet[35] = static_cast<std::byte>(src_port & 0xFFU);
    packet[36] = static_cast<std::byte>((dst_port >> 8U) & 0xFFU);
    packet[37] = static_cast<std::byte>(dst_port & 0xFFU);
    packet[38] = static_cast<std::byte>((udp_total_length >> 8U) & 0xFFU);
    packet[39] = static_cast<std::byte>(udp_total_length & 0xFFU);

    std::copy(payload.begin(), payload.end(), packet.begin() + static_cast<std::ptrdiff_t>(kIpv4UdpPayloadOffset));
    return packet;
}

pcap_constrictor_afpacket::PacketDecodeResult DecodeOrFail(const std::vector<std::byte>& packet) {
    return pcap_constrictor_afpacket::DecodePacket(std::span(packet));
}

}  // namespace

int RunQuicConstrictorTests() {
    using namespace pcap_constrictor_afpacket;

    const std::vector<std::byte> long_header_payload{
        std::byte{0xc0},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x04},
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x04},
        std::byte{0xaa}, std::byte{0xab}, std::byte{0xac}, std::byte{0xad},
    };

    const std::vector<std::byte> matching_short_payload{
        std::byte{0x40},
        std::byte{0xaa}, std::byte{0xab}, std::byte{0xac}, std::byte{0xad},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef},
    };

    PolicyConfig::QuicOptions quic_config;
    quic_config.short_header_keep_packet_bytes = 2U;
    quic_config.require_dcid_match = true;
    quic_config.allow_short_header_without_known_dcid = false;

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(long_header_payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result = constrictor.Evaluate(std::span(packet), decoded, quic_config);

        if (decoded.failure_reason != PacketDecodeFailureReason::None) {
            return Fail("valid QUIC long-header UDP packet should decode");
        }
        if (result.disposition != QuicConstrictDisposition::LongHeader) {
            return Fail("long header should be learned and kept conservatively");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> long_packet = BuildIpv4UdpPacket(long_header_payload);
        const PacketDecodeResult long_decoded = DecodeOrFail(long_packet);
        static_cast<void>(constrictor.Evaluate(std::span(long_packet), long_decoded, quic_config));

        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(matching_short_payload, 443U, 5555U, 2U, 1U);
        const PacketDecodeResult short_decoded = DecodeOrFail(short_packet);
        const QuicConstrictResult result =
            constrictor.Evaluate(std::span(short_packet), short_decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::ShortHeaderMatched) {
            return Fail("matching short header should be constricted after CID learning");
        }
        if (result.output_len != kIpv4UdpPayloadOffset + 5U) {
            return Fail("short-header keep length should preserve at least first byte plus learned DCID");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(matching_short_payload, 443U, 5555U, 2U, 1U);
        const PacketDecodeResult decoded = DecodeOrFail(short_packet);
        const QuicConstrictResult result =
            constrictor.Evaluate(std::span(short_packet), decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::UnknownCidFallback) {
            return Fail("unknown expected CID should fall back when matching is required");
        }
    }

    {
        QuicConstrictor constrictor;
        PolicyConfig::QuicOptions permissive = quic_config;
        permissive.require_dcid_match = false;
        permissive.allow_short_header_without_known_dcid = true;
        permissive.short_header_keep_packet_bytes = 3U;

        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(matching_short_payload, 443U, 5555U, 2U, 1U);
        const PacketDecodeResult decoded = DecodeOrFail(short_packet);
        const QuicConstrictResult result =
            constrictor.Evaluate(std::span(short_packet), decoded, permissive);

        if (result.disposition != QuicConstrictDisposition::ShortHeaderMatched) {
            return Fail("unknown short header should be conservatively constricted when permissive mode is enabled");
        }
        if (result.output_len != kIpv4UdpPayloadOffset + 3U) {
            return Fail("permissive short-header fallback should keep the configured fixed prefix");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> long_packet = BuildIpv4UdpPacket(long_header_payload);
        const PacketDecodeResult long_decoded = DecodeOrFail(long_packet);
        static_cast<void>(constrictor.Evaluate(std::span(long_packet), long_decoded, quic_config));

        const std::vector<std::byte> mismatched_short_payload{
            std::byte{0x40},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0xde}, std::byte{0xad},
        };
        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(mismatched_short_payload, 443U, 5555U, 2U, 1U);
        const PacketDecodeResult decoded = DecodeOrFail(short_packet);
        const QuicConstrictResult result =
            constrictor.Evaluate(std::span(short_packet), decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::DcidMismatchFallback) {
            return Fail("mismatched expected DCID should fall back conservatively");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0xc0},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        };
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result = constrictor.Evaluate(std::span(packet), decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::MalformedFallback) {
            return Fail("truncated QUIC long header should fall back conservatively");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0xc0},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x04},
            std::byte{0x11}, std::byte{0x12},
        };
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result = constrictor.Evaluate(std::span(packet), decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::MalformedFallback) {
            return Fail("declared CID length larger than available payload should fall back");
        }
    }

    {
        QuicConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0xc0},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x15},
            std::byte{0x00},
        };
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result = constrictor.Evaluate(std::span(packet), decoded, quic_config);

        if (result.disposition != QuicConstrictDisposition::MalformedFallback) {
            return Fail("CID length above maximum should fall back");
        }
    }

    {
        QuicConstrictor constrictor;
        PolicyConfig::QuicOptions disabled = quic_config;
        disabled.enabled = false;
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(long_header_payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result = constrictor.Evaluate(std::span(packet), decoded, disabled);

        if (result.disposition != QuicConstrictDisposition::NotApplicable) {
            return Fail("disabled QUIC config should skip constriction");
        }
    }

    {
        QuicConstrictor constrictor;
        PolicyConfig::QuicOptions different_ports = quic_config;
        different_ports.ports = {8443U};
        const std::vector<std::byte> packet = BuildIpv4UdpPacket(long_header_payload);
        const PacketDecodeResult decoded = DecodeOrFail(packet);
        const QuicConstrictResult result =
            constrictor.Evaluate(std::span(packet), decoded, different_ports);

        if (result.disposition != QuicConstrictDisposition::NotApplicable) {
            return Fail("UDP packets on unconfigured ports should skip QUIC constriction");
        }
    }

    return 0;
}
