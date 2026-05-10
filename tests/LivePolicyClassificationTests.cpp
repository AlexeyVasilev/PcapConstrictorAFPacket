#include <array>
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

int Fail(std::string_view message) {
    std::cerr << "[LivePolicyClassificationTests] " << message << '\n';
    return 1;
}

pcap_constrictor_afpacket::CapturedPacket MakePacket(std::span<const std::byte> bytes,
                                                     std::uint32_t captured_len,
                                                     std::uint32_t original_len) {
    using namespace pcap_constrictor_afpacket;
    return CapturedPacket{
        .packet = PacketView(bytes, captured_len, original_len),
        .timestamp = std::chrono::system_clock::time_point{},
        .ifindex = 0,
        .direction = PacketDirection::Unknown,
    };
}

}  // namespace

int RunLivePolicyClassificationTests() {
    using namespace pcap_constrictor_afpacket;

    constexpr std::array<std::byte, 54> tcp443{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x50}, std::byte{0x18}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };

    constexpr std::array<std::byte, 57> udp443{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2b}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x11}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x15}, std::byte{0xb3}, std::byte{0x01}, std::byte{0xbb},
        std::byte{0x00}, std::byte{0x17}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x04},
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x04},
        std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
    };

    constexpr std::array<std::byte, 65> tlsAppData443{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x33}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x50}, std::byte{0x18}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}, std::byte{0xca}, std::byte{0xfe},
    };

    const std::vector<std::byte> nonTls443{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2e}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x50}, std::byte{0x18}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x47}, std::byte{0x45}, std::byte{0x54}, std::byte{0x20}, std::byte{0x2f}, std::byte{0x20},
    };

    const std::vector<std::byte> truncatedTls443{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2c}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x30}, std::byte{0x39}, std::byte{0x01}, std::byte{0xbb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x50}, std::byte{0x18}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00},
    };

    {
        PolicyConfig config;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(tcp443), static_cast<std::uint32_t>(tcp443.size()), 128U));

        if (decision.reason != DecisionReason::TlsCandidate) {
            return Fail("TCP 443 should classify as TlsCandidate when TLS is enabled");
        }
        if (decision.output_len != tcp443.size()) {
            return Fail("policy clamp should remain unchanged for TLS candidate");
        }
    }

    {
        PolicyConfig config;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(udp443), static_cast<std::uint32_t>(udp443.size()), 128U));

        if (decision.reason != DecisionReason::QuicLongHeader) {
            return Fail("Valid QUIC long-header UDP 443 should classify as QuicLongHeader");
        }
    }

    {
        PolicyConfig config;
        config.capture.default_snaplen = 256U;
        config.capture.max_capture_len = 256U;
        config.tls.app_data_keep_record_bytes = 2U;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision = policy.Evaluate(
            MakePacket(std::span(tlsAppData443), static_cast<std::uint32_t>(tlsAppData443.size()), 128U));

        if (decision.reason != DecisionReason::TlsApplicationDataConstricted) {
            return Fail("TLS AppData packet should report TlsApplicationDataConstricted");
        }
        if (decision.output_len >= tlsAppData443.size()) {
            return Fail("TLS AppData packet should be shortened when keep bytes are small");
        }
    }

    {
        PolicyConfig config;
        config.tls.enabled = false;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(tcp443), static_cast<std::uint32_t>(tcp443.size()), 128U));

        if (decision.reason != DecisionReason::Tcp) {
            return Fail("TCP 443 should fall back to Tcp when TLS is disabled");
        }
    }

    {
        PolicyConfig config;
        config.tls.enabled = false;
        config.tls.app_data_keep_record_bytes = 2U;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision = policy.Evaluate(
            MakePacket(std::span(tlsAppData443), static_cast<std::uint32_t>(tlsAppData443.size()), 128U));

        if (decision.reason != DecisionReason::Tcp) {
            return Fail("TLS payload should stay plain Tcp when TLS is disabled");
        }
    }

    {
        PolicyConfig config;
        config.tls.ports = {8443U};
        config.tls.app_data_keep_record_bytes = 2U;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision = policy.Evaluate(
            MakePacket(std::span(tlsAppData443), static_cast<std::uint32_t>(tlsAppData443.size()), 128U));

        if (decision.reason != DecisionReason::Tcp) {
            return Fail("TLS payload should stay plain Tcp when port is not configured");
        }
    }

    {
        PolicyConfig config;
        config.quic.enabled = false;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(udp443), static_cast<std::uint32_t>(udp443.size()), 128U));

        if (decision.reason != DecisionReason::Udp) {
            return Fail("QUIC long-header packet should fall back to Udp when QUIC is disabled");
        }
    }

    {
        PolicyConfig config;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision = policy.Evaluate(
            MakePacket(std::span(nonTls443), static_cast<std::uint32_t>(nonTls443.size()), 128U));

        if (decision.reason != DecisionReason::TlsNoRecordFallback) {
            return Fail("Non-TLS payload on port 443 should report TlsNoRecordFallback");
        }
    }

    {
        PolicyConfig config;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision = policy.Evaluate(
            MakePacket(std::span(truncatedTls443), static_cast<std::uint32_t>(truncatedTls443.size()), 128U));

        if (decision.reason != DecisionReason::TlsMalformedFallback) {
            return Fail("Truncated TLS record should report TlsMalformedFallback");
        }
    }

    {
        constexpr std::array<std::byte, 18> malformed{
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
            std::byte{0x08}, std::byte{0x00},
            std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28},
        };

        PolicyConfig config;
        config.capture.default_snaplen = 16U;
        config.capture.max_capture_len = 32U;
        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(malformed), static_cast<std::uint32_t>(malformed.size()), 64U));

        if (decision.reason != DecisionReason::ParseError) {
            return Fail("malformed packet should classify as ParseError");
        }
        if (decision.output_len != 16U) {
            return Fail("malformed packet should still use conservative length clamp");
        }
    }

    return 0;
}
