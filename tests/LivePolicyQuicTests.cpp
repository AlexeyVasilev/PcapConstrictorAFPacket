#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "capture/CapturedPacket.hpp"
#include "policy/LiveCapturePolicy.hpp"

namespace {

constexpr std::size_t kIpv4UdpPayloadOffset = 42U;

int Fail(std::string_view message) {
    std::cerr << "[LivePolicyQuicTests] " << message << '\n';
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

pcap_constrictor_afpacket::CapturedPacket MakePacket(const std::vector<std::byte>& bytes) {
    using namespace pcap_constrictor_afpacket;
    return CapturedPacket{
        .packet = PacketView(std::span(bytes), static_cast<std::uint32_t>(bytes.size()), static_cast<std::uint32_t>(bytes.size())),
        .timestamp = std::chrono::system_clock::time_point{},
        .ifindex = 0,
        .direction = PacketDirection::Unknown,
    };
}

}  // namespace

int RunLivePolicyQuicTests() {
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

    {
        PolicyConfig config;
        config.capture.default_snaplen = 256U;
        config.capture.max_capture_len = 256U;
        config.quic.short_header_keep_packet_bytes = 2U;
        config.quic.require_dcid_match = true;
        config.quic.allow_short_header_without_known_dcid = false;

        LiveCapturePolicy policy(config);
        const std::vector<std::byte> long_packet = BuildIpv4UdpPacket(long_header_payload);
        const LiveCaptureDecision long_decision = policy.Evaluate(MakePacket(long_packet));
        if (long_decision.reason != DecisionReason::QuicLongHeader) {
            return Fail("QUIC long header should be classified and learned before short-header matching");
        }

        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(matching_short_payload, 443U, 5555U, 2U, 1U);
        const LiveCaptureDecision short_decision = policy.Evaluate(MakePacket(short_packet));
        if (short_decision.reason != DecisionReason::QuicShortHeaderConstricted) {
            return Fail("matched QUIC short header should be constricted after prior CID learning");
        }
        if (short_decision.output_len != kIpv4UdpPayloadOffset + 5U) {
            return Fail("QUIC short-header constriction length mismatch");
        }
        if (short_decision.output_len >= short_packet.size()) {
            return Fail("matched QUIC short header should shrink the saved packet when keep bytes are small");
        }
    }

    {
        PolicyConfig config;
        config.quic.short_header_keep_packet_bytes = 2U;
        config.quic.require_dcid_match = true;
        config.quic.allow_short_header_without_known_dcid = false;

        LiveCapturePolicy fresh_policy(config);
        const std::vector<std::byte> short_packet =
            BuildIpv4UdpPacket(matching_short_payload, 443U, 5555U, 2U, 1U);
        const LiveCaptureDecision short_decision = fresh_policy.Evaluate(MakePacket(short_packet));

        if (short_decision.reason != DecisionReason::QuicShortHeaderUnknownCidFallback) {
            return Fail("fresh policy instance should not constrict short header before Long Header CID learning");
        }
    }

    return 0;
}
