#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <span>
#include <string_view>

#include "capture/CapturedPacket.hpp"
#include "policy/LiveCapturePolicy.hpp"
#include "writer/PcapWriter.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[LivePolicySmokeTests] " << message << '\n';
    return 1;
}

pcap_constrictor_afpacket::CapturedPacket MakePacket(std::span<const std::byte> bytes,
                                                     std::uint32_t captured_len,
                                                     std::uint32_t original_len) {
    using namespace pcap_constrictor_afpacket;
    return CapturedPacket{
        .packet = PacketView(bytes, captured_len, original_len),
        .timestamp = std::chrono::system_clock::time_point{},
        .ifindex = 1,
        .direction = PacketDirection::Unknown,
    };
}

}  // namespace

int RunLivePolicySmokeTests() {
    using namespace pcap_constrictor_afpacket;

    constexpr std::array<std::byte, 128> bytes{};

    {
        PolicyConfig config;
        config.capture.default_snaplen = 96U;
        config.capture.max_capture_len = 80U;

        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(bytes), 128U, 512U));

        if (decision.output_len != 80U) {
            return Fail("max_capture_len should clamp output length");
        }
        if (decision.original_len != 512U) {
            return Fail("original length should be preserved");
        }
        if (decision.reason != DecisionReason::NonIp) {
            return Fail("non-IP packet should classify as NonIp");
        }
    }

    {
        PolicyConfig config;
        config.capture.default_snaplen = 64U;
        config.capture.max_capture_len = 64U;

        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(bytes), 128U, 128U));

        if (decision.output_len != 64U) {
            return Fail("equal limits should clamp to 64 bytes");
        }
        if (decision.reason != DecisionReason::NonIp) {
            return Fail("zeroed Ethernet frame should classify as NonIp");
        }
    }

    {
        PolicyConfig config;
        config.capture.default_snaplen = 256U;
        config.capture.max_capture_len = 256U;

        LiveCapturePolicy policy(config);
        const LiveCaptureDecision decision =
            policy.Evaluate(MakePacket(std::span(bytes), 100U, 90U));

        if (decision.output_len != 90U) {
            return Fail("malformed packet should clamp conservatively to original length");
        }
        if (decision.original_len != 90U) {
            return Fail("malformed packet original length should remain conservative");
        }
        if (decision.reason != DecisionReason::ParseError) {
            return Fail("malformed packet should classify as ParseError");
        }
    }

    {
        PolicyConfig config;
        config.capture.default_snaplen = 60U;
        config.capture.max_capture_len = 60U;

        LiveCapturePolicy policy(config);
        const CapturedPacket packet = MakePacket(std::span(bytes), 90U, 120U);
        const LiveCaptureDecision decision = policy.Evaluate(packet);

        std::ostringstream sink(std::ios::out | std::ios::binary);
        PcapWriter writer(sink, config.capture.max_capture_len);
        writer.WritePacket(packet, decision.output_len);

        if (sink.str().size() != 24U + 16U + 60U) {
            return Fail("offline packet-feed smoke path wrote unexpected PCAP size");
        }
    }

    return 0;
}
