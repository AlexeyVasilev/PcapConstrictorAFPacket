#pragma once

#include <cstdint>
#include <string_view>

#include "capture/CapturedPacket.hpp"
#include "decode/PacketDecode.hpp"
#include "policy/PolicyConfig.hpp"
#include "policy/QuicConstrictor.hpp"

namespace pcap_constrictor_afpacket {

enum class DecisionReason {
    Default,
    ParseError,
    NonIp,
    Tcp,
    Udp,
    TlsCandidate,
    TlsApplicationDataConstricted,
    TlsMalformedFallback,
    TlsNoRecordFallback,
    QuicCandidate,
    QuicLongHeader,
    QuicShortHeaderMatched,
    QuicShortHeaderConstricted,
    QuicShortHeaderUnknownCidFallback,
    QuicShortHeaderDcidMismatchFallback,
    QuicMalformedFallback,
};

struct LiveCaptureDecision {
    std::uint32_t output_len{0};
    std::uint32_t original_len{0};
    DecisionReason reason{DecisionReason::Default};
    PacketDecodeResult decode{};

    [[nodiscard]] std::string_view reason_string() const noexcept;
};

class LiveCapturePolicy {
public:
    explicit LiveCapturePolicy(PolicyConfig config) noexcept;

    [[nodiscard]] LiveCaptureDecision Evaluate(const CapturedPacket& packet) noexcept;
    [[nodiscard]] const PolicyConfig& config() const noexcept;

private:
    PolicyConfig config_;
    QuicConstrictor quic_constrictor_{};
};

}  // namespace pcap_constrictor_afpacket
