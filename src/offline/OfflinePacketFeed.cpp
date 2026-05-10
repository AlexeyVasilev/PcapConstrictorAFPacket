#include "offline/OfflinePacketFeed.hpp"

#include <algorithm>
#include <fstream>
#include <span>
#include <stdexcept>

#include "capture/CapturedPacket.hpp"
#include "offline/PcapReader.hpp"
#include "policy/LiveCapturePolicy.hpp"
#include "writer/PcapWriter.hpp"

namespace pcap_constrictor_afpacket {

namespace {

void AccumulateDecisionStats(CaptureStats& stats, const DecisionReason reason) {
    switch (reason) {
        case DecisionReason::TlsApplicationDataConstricted:
            ++stats.tls_appdata_constricted;
            break;
        case DecisionReason::TlsMalformedFallback:
        case DecisionReason::TlsNoRecordFallback:
            ++stats.tls_fallback;
            break;
        case DecisionReason::QuicLongHeader:
            ++stats.quic_long_header;
            break;
        case DecisionReason::QuicShortHeaderMatched:
            ++stats.quic_short_matched;
            break;
        case DecisionReason::QuicShortHeaderConstricted:
            ++stats.quic_short_constricted;
            break;
        case DecisionReason::QuicShortHeaderUnknownCidFallback:
        case DecisionReason::QuicShortHeaderDcidMismatchFallback:
        case DecisionReason::QuicMalformedFallback:
            ++stats.quic_fallback;
            break;
        default:
            break;
    }
}

}  // namespace

OfflinePacketFeedResult OfflinePacketFeed::Run(const std::filesystem::path& input_path,
                                               const std::filesystem::path& output_path,
                                               const PolicyConfig& config) {
    OfflinePacketFeedResult result;

    PcapReader reader;
    if (!reader.Open(input_path)) {
        result.error = reader.error_message();
        return result;
    }

    std::ofstream output_stream(output_path, std::ios::binary);
    if (!output_stream) {
        result.error = "failed to open output file";
        return result;
    }

    const std::uint32_t output_snaplen =
        std::min(config.capture.default_snaplen, config.capture.max_capture_len);
    PcapWriter writer(output_stream, output_snaplen);
    LiveCapturePolicy policy(config);

    try {
        while (const std::optional<PcapPacketRecord> record = reader.ReadNext()) {
            const CapturedPacket packet{
                .packet = PacketView(std::span<const std::byte>(record->bytes.data(), record->bytes.size()),
                                     record->captured_length,
                                     record->original_length),
                .timestamp = record->timestamp(reader.global_header().time_precision),
                .ifindex = 0,
                .direction = PacketDirection::Unknown,
            };

            const LiveCaptureDecision decision = policy.Evaluate(packet);
            writer.WritePacket(packet, decision.output_len);

            ++result.stats.packets_total;
            ++result.stats.packets_written;
            result.stats.bytes_input += record->captured_length;
            result.stats.bytes_output += decision.output_len;
            AccumulateDecisionStats(result.stats, decision.reason);
        }
    } catch (const std::exception& exception) {
        result.error = exception.what();
        return result;
    }

    if (reader.has_error()) {
        result.error = reader.error_message();
        return result;
    }

    result.stats.bytes_saved = result.stats.bytes_input - result.stats.bytes_output;
    return result;
}

}  // namespace pcap_constrictor_afpacket
