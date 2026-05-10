#include "policy/LiveCapturePolicy.hpp"

#include <algorithm>
#include <utility>

namespace pcap_constrictor_afpacket {

std::string_view LiveCaptureDecision::reason_string() const noexcept {
    switch (reason) {
        case DecisionReason::PassThrough:
            return "pass_through";
        case DecisionReason::ClampedToDefaultSnaplen:
            return "clamped_to_default_snaplen";
        case DecisionReason::ClampedToMaxCaptureLen:
            return "clamped_to_max_capture_len";
        case DecisionReason::ClampedToBothLimits:
            return "clamped_to_both_limits";
        case DecisionReason::MalformedPacket:
            return "malformed_packet";
    }

    return "unknown";
}

LiveCapturePolicy::LiveCapturePolicy(PolicyConfig config) noexcept
    : config_(std::move(config)) {}

LiveCaptureDecision LiveCapturePolicy::Evaluate(const CapturedPacket& packet) const noexcept {
    const std::uint32_t safe_captured_len = packet.packet.safe_captured_len();
    const std::uint32_t conservative_original_len =
        std::max(packet.original_len(), safe_captured_len);

    const bool malformed =
        packet.captured_len() > packet.data().size() || packet.original_len() < safe_captured_len;

    const std::uint32_t snaplen_limit = config_.capture.default_snaplen;
    const std::uint32_t max_capture_limit = config_.capture.max_capture_len;
    const std::uint32_t output_len =
        std::min({safe_captured_len, snaplen_limit, max_capture_limit});

    DecisionReason reason = DecisionReason::PassThrough;
    if (malformed) {
        reason = DecisionReason::MalformedPacket;
    } else {
        if (output_len == safe_captured_len) {
            reason = DecisionReason::PassThrough;
        } else if (snaplen_limit == max_capture_limit) {
            reason = DecisionReason::ClampedToBothLimits;
        } else if (snaplen_limit < max_capture_limit) {
            reason = DecisionReason::ClampedToDefaultSnaplen;
        } else {
            reason = DecisionReason::ClampedToMaxCaptureLen;
        }
    }

    // TODO: Add PcapConstrictor-compatible TLS/QUIC adapters here after live input exists.
    return LiveCaptureDecision{
        .output_len = output_len,
        .original_len = conservative_original_len,
        .reason = reason,
    };
}

const PolicyConfig& LiveCapturePolicy::config() const noexcept {
    return config_;
}

}  // namespace pcap_constrictor_afpacket
