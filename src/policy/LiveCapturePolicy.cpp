#include "policy/LiveCapturePolicy.hpp"

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

#include "policy/QuicConstrictor.hpp"
#include "policy/TlsConstrictor.hpp"

namespace pcap_constrictor_afpacket {

namespace {

bool PortConfigured(const std::vector<std::uint16_t>& ports, const std::uint16_t port) noexcept {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

std::uint32_t ApplyMinimumSavingsThreshold(const std::uint32_t baseline_output_len,
                                           const std::uint32_t candidate_output_len,
                                           const std::uint32_t min_saved_bytes_per_packet) noexcept {
    if (candidate_output_len >= baseline_output_len) {
        return baseline_output_len;
    }

    const std::uint32_t saved_bytes = baseline_output_len - candidate_output_len;
    if (saved_bytes < min_saved_bytes_per_packet) {
        return baseline_output_len;
    }

    return candidate_output_len;
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
        case DecisionReason::QuicLongHeader:
            return "quic_long_header";
        case DecisionReason::QuicShortHeaderMatched:
            return "quic_short_header_matched";
        case DecisionReason::QuicShortHeaderConstricted:
            return "quic_short_header_constricted";
        case DecisionReason::QuicShortHeaderUnknownCidFallback:
            return "quic_short_header_unknown_cid_fallback";
        case DecisionReason::QuicShortHeaderDcidMismatchFallback:
            return "quic_short_header_dcid_mismatch_fallback";
        case DecisionReason::QuicMalformedFallback:
            return "quic_malformed_fallback";
    }

    return "unknown";
}

LiveCapturePolicy::LiveCapturePolicy(PolicyConfig config) noexcept
    : config_(std::move(config)) {}

LiveCaptureDecision LiveCapturePolicy::Evaluate(const CapturedPacket& packet) noexcept {
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
        const TlsConstrictResult tls_result = tls_constrictor_.Evaluate(
            std::span<const std::byte>(packet.data().data(), safe_captured_len),
            decoded,
            config_.tls);

        if (tls_result.disposition == TlsConstrictDisposition::AppDataPrefix) {
            final_output_len = ApplyMinimumSavingsThreshold(
                output_len,
                std::min(output_len, tls_result.output_len),
                config_.general.min_saved_bytes_per_packet);
            if (final_output_len < output_len) {
                reason = DecisionReason::TlsApplicationDataConstricted;
            }
        } else if (tls_result.disposition == TlsConstrictDisposition::Malformed ||
                   tls_result.disposition == TlsConstrictDisposition::UncertainFallback) {
            reason = DecisionReason::TlsMalformedFallback;
        } else if (tls_result.disposition == TlsConstrictDisposition::NoRecord) {
            reason = DecisionReason::TlsNoRecordFallback;
        }
    } else if (!malformed &&
               decoded.failure_reason == PacketDecodeFailureReason::None &&
               reason == DecisionReason::QuicCandidate &&
               decoded.transport_payload_length > 0U) {
        const QuicConstrictResult quic_result = quic_constrictor_.Evaluate(
            std::span<const std::byte>(packet.data().data(), safe_captured_len),
            decoded,
            config_.quic);

        if (quic_result.disposition == QuicConstrictDisposition::LongHeader) {
            reason = DecisionReason::QuicLongHeader;
        } else if (quic_result.disposition == QuicConstrictDisposition::ShortHeaderMatched) {
            final_output_len = ApplyMinimumSavingsThreshold(
                output_len,
                std::min(output_len, quic_result.output_len),
                config_.general.min_saved_bytes_per_packet);
            reason = final_output_len < output_len
                         ? DecisionReason::QuicShortHeaderConstricted
                         : DecisionReason::QuicShortHeaderMatched;
        } else if (quic_result.disposition == QuicConstrictDisposition::UnknownCidFallback) {
            reason = DecisionReason::QuicShortHeaderUnknownCidFallback;
        } else if (quic_result.disposition == QuicConstrictDisposition::DcidMismatchFallback) {
            reason = DecisionReason::QuicShortHeaderDcidMismatchFallback;
        } else if (quic_result.disposition == QuicConstrictDisposition::MalformedFallback) {
            reason = DecisionReason::QuicMalformedFallback;
        }
    }

    // TODO: Add deeper PcapConstrictor-compatible TLS/QUIC adapters here without changing capture plumbing.
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
