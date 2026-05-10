#include "policy/LiveCapturePolicy.hpp"

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

#include "policy/TlsConstrictor.hpp"

namespace pcap_constrictor_afpacket {

namespace {

bool PortConfigured(const std::vector<std::uint16_t>& ports, const std::uint16_t port) noexcept {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

}  // namespace

std::string_view LiveCaptureDecision::reason_string() const noexcept {
    switch (reason) {
        case DecisionReason::Default:
            return "default";
        case DecisionReason::ParseError:
            return "parse_error";
        case DecisionReason::NonIp:
            return "non_ip";
        case DecisionReason::Tcp:
            return "tcp";
        case DecisionReason::Udp:
            return "udp";
        case DecisionReason::TlsCandidate:
            return "tls_candidate";
        case DecisionReason::TlsApplicationDataConstricted:
            return "tls_application_data_constricted";
        case DecisionReason::TlsMalformedFallback:
            return "tls_malformed_fallback";
        case DecisionReason::TlsNoRecordFallback:
            return "tls_no_record_fallback";
        case DecisionReason::QuicCandidate:
            return "quic_candidate";
    }

    return "unknown";
}

LiveCapturePolicy::LiveCapturePolicy(PolicyConfig config) noexcept
    : config_(std::move(config)) {}

LiveCaptureDecision LiveCapturePolicy::Evaluate(const CapturedPacket& packet) const noexcept {
    const std::uint32_t safe_captured_len = packet.packet.safe_captured_len();
    const std::uint32_t effective_input_len =
        std::min(safe_captured_len, packet.original_len());

    const bool malformed =
        packet.captured_len() > packet.data().size() || packet.original_len() < safe_captured_len;

    const std::uint32_t snaplen_limit = config_.capture.default_snaplen;
    const std::uint32_t max_capture_limit = config_.capture.max_capture_len;
    const std::uint32_t output_len =
        std::min({effective_input_len, snaplen_limit, max_capture_limit});
    const std::uint32_t conservative_original_len =
        std::max(packet.original_len(), output_len);

    PacketDecodeResult decoded =
        DecodePacket(std::span<const std::byte>(packet.data().data(), safe_captured_len));

    DecisionReason reason = DecisionReason::Default;
    if (malformed) {
        reason = DecisionReason::ParseError;
    } else if (decoded.failure_reason != PacketDecodeFailureReason::None) {
        reason = DecisionReason::ParseError;
    } else {
        if (decoded.is_non_ip()) {
            reason = DecisionReason::NonIp;
        } else if (decoded.transport_protocol == TransportProtocol::Tcp) {
            const bool tls_candidate =
                config_.tls.enabled &&
                (PortConfigured(config_.tls.ports, decoded.src_port) ||
                 PortConfigured(config_.tls.ports, decoded.dst_port));
            reason = tls_candidate ? DecisionReason::TlsCandidate : DecisionReason::Tcp;
        } else if (decoded.transport_protocol == TransportProtocol::Udp) {
            const bool quic_candidate =
                config_.quic.enabled &&
                (PortConfigured(config_.quic.ports, decoded.src_port) ||
                 PortConfigured(config_.quic.ports, decoded.dst_port));
            reason = quic_candidate ? DecisionReason::QuicCandidate : DecisionReason::Udp;
        }
    }

    std::uint32_t final_output_len = output_len;
    if (!malformed &&
        decoded.failure_reason == PacketDecodeFailureReason::None &&
        reason == DecisionReason::TlsCandidate &&
        decoded.transport_payload_length > 0U) {
        const TlsConstrictResult tls_result = TlsConstrictor::Evaluate(
            std::span<const std::byte>(packet.data().data(), safe_captured_len),
            decoded.transport_payload_offset,
            decoded.transport_payload_length,
            config_.tls);

        if (tls_result.disposition == TlsConstrictDisposition::AppDataPrefix) {
            final_output_len = std::min(output_len, tls_result.output_len);
            if (final_output_len < output_len) {
                reason = DecisionReason::TlsApplicationDataConstricted;
            }
        } else if (tls_result.disposition == TlsConstrictDisposition::Malformed) {
            reason = DecisionReason::TlsMalformedFallback;
        } else if (tls_result.disposition == TlsConstrictDisposition::NoRecord) {
            reason = DecisionReason::TlsNoRecordFallback;
        }
    }

    // TODO: Add PcapConstrictor-compatible TLS/QUIC adapters here after live input exists.
    return LiveCaptureDecision{
        .output_len = final_output_len,
        .original_len = conservative_original_len,
        .reason = reason,
        .decode = decoded,
    };
}

const PolicyConfig& LiveCapturePolicy::config() const noexcept {
    return config_;
}

}  // namespace pcap_constrictor_afpacket
