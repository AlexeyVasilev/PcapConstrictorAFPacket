#pragma once

#include <cstdint>
#include <string_view>

#include "capture/CapturedPacket.hpp"
#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

enum class DecisionReason {
    PassThrough,
    ClampedToDefaultSnaplen,
    ClampedToMaxCaptureLen,
    ClampedToBothLimits,
    MalformedPacket,
};

struct LiveCaptureDecision {
    std::uint32_t output_len{0};
    std::uint32_t original_len{0};
    DecisionReason reason{DecisionReason::PassThrough};

    [[nodiscard]] std::string_view reason_string() const noexcept;
};

class LiveCapturePolicy {
public:
    explicit LiveCapturePolicy(PolicyConfig config) noexcept;

    [[nodiscard]] LiveCaptureDecision Evaluate(const CapturedPacket& packet) const noexcept;
    [[nodiscard]] const PolicyConfig& config() const noexcept;

private:
    PolicyConfig config_;
};

}  // namespace pcap_constrictor_afpacket
