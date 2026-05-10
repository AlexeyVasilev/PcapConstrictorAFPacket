#include <algorithm>
#include <csignal>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

#if defined(__linux__)
#include <signal.h>
#endif

#include "capture/AfPacketCapture.hpp"
#include "config/ConfigLoader.hpp"
#include "offline/OfflinePacketFeed.hpp"
#include "policy/LiveCapturePolicy.hpp"
#include "stats/CaptureStats.hpp"
#include "writer/PcapWriter.hpp"

namespace pcap_constrictor_afpacket {
namespace {

volatile std::sig_atomic_t g_stop_requested = 0;

void HandleStopSignal(int) {
    g_stop_requested = 1;
}

void PrintUsage(std::ostream& output) {
    output << "Usage:\n"
           << "  PcapConstrictorAFPacket --config <config.ini>\n"
           << "  PcapConstrictorAFPacket --config <config.ini> --offline-input <input.pcap>\n"
           << "  PcapConstrictorAFPacket --help\n";
}

void InstallSignalHandlers() {
#if defined(__linux__)
    struct sigaction action {};
    action.sa_handler = HandleStopSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGINT, &action, nullptr);
#ifdef SIGTERM
    sigaction(SIGTERM, &action, nullptr);
#endif
#else
    std::signal(SIGINT, HandleStopSignal);
#ifdef SIGTERM
    std::signal(SIGTERM, HandleStopSignal);
#endif
#endif
}

void PrintCaptureStats(std::ostream& output, const CaptureStats& stats) {
    output << "packets_total: " << stats.packets_total << '\n'
           << "packets_written: " << stats.packets_written << '\n'
           << "bytes_input: " << stats.bytes_input << '\n'
           << "bytes_output: " << stats.bytes_output << '\n'
           << "bytes_saved: " << stats.bytes_saved << '\n'
           << "tls_appdata_constricted: " << stats.tls_appdata_constricted << '\n'
           << "tls_fallback: " << stats.tls_fallback << '\n'
           << "quic_long_header: " << stats.quic_long_header << '\n'
           << "quic_short_matched: " << stats.quic_short_matched << '\n'
           << "quic_short_constricted: " << stats.quic_short_constricted << '\n'
           << "quic_fallback: " << stats.quic_fallback << '\n';
}

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

int RunLiveCapture(const PolicyConfig& config) {
    if (config.capture.interface.empty()) {
        std::cerr << "Configuration error: capture.interface is required for live capture.\n";
        return 1;
    }

    g_stop_requested = 0;
    InstallSignalHandlers();

    const std::uint32_t output_snaplen =
        std::min(config.capture.default_snaplen, config.capture.max_capture_len);
    const std::uint32_t receive_buffer_size =
        std::max(config.capture.max_capture_len, 65535U);

    AfPacketCapture capture(receive_buffer_size);
    if (!capture.Open(config.capture.interface)) {
        std::cerr << "Live capture error: " << capture.error_message() << '\n';
        return 1;
    }

    std::ofstream output_stream(config.capture.output, std::ios::binary);
    if (!output_stream) {
        std::cerr << "Live capture error: failed to open output file '"
                  << config.capture.output.string() << "'.\n";
        return 1;
    }

    PcapWriter writer(output_stream, output_snaplen);
    LiveCapturePolicy policy(config);
    CaptureStats stats;

    try {
        writer.WriteGlobalHeader();
    } catch (const std::exception& exception) {
        std::cerr << "Live capture error: " << exception.what() << '\n';
        return 1;
    }

    std::cout << "Starting live capture on interface '" << config.capture.interface
              << "'. Press Ctrl+C to stop.\n"
              << "Writing output to '" << config.capture.output.string() << "'.\n";

    while (g_stop_requested == 0) {
        CapturedPacket packet;
        const AfPacketReceiveStatus status =
            capture.ReceiveNext(packet, &g_stop_requested);

        if (status == AfPacketReceiveStatus::Interrupted) {
            break;
        }

        if (status == AfPacketReceiveStatus::Error) {
            std::cerr << "Live capture error: " << capture.error_message() << '\n';
            return 1;
        }

        const LiveCaptureDecision decision = policy.Evaluate(packet);

        try {
            writer.WritePacket(packet, decision.output_len);
        } catch (const std::exception& exception) {
            std::cerr << "Live capture error: " << exception.what() << '\n';
            return 1;
        }

        ++stats.packets_total;
        ++stats.packets_written;
        stats.bytes_input += packet.captured_len();
        stats.bytes_output += decision.output_len;
        AccumulateDecisionStats(stats, decision.reason);
    }

    stats.bytes_saved = stats.bytes_input - stats.bytes_output;
    std::cout << "Live capture stopped.\n";
    PrintCaptureStats(std::cout, stats);
    return 0;
}

}  // namespace
}  // namespace pcap_constrictor_afpacket

int main(int argc, char* argv[]) {
    using namespace pcap_constrictor_afpacket;

    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        PrintUsage(std::cout);
        return 0;
    }

    const bool config_only =
        argc == 3 && std::string_view(argv[1]) == "--config";
    const bool offline_mode =
        argc == 5 &&
        std::string_view(argv[1]) == "--config" &&
        std::string_view(argv[3]) == "--offline-input";

    if (!config_only && !offline_mode) {
        PrintUsage(std::cerr);
        return 1;
    }

    const ConfigLoadResult result = ConfigLoader::LoadFromFile(argv[2]);
    if (!result) {
        std::cerr << "Configuration error: " << result.error << '\n';
        return 1;
    }

    if (offline_mode) {
        const std::filesystem::path input_path = argv[4];
        const std::filesystem::path output_path = result.config.capture.output;
        const OfflinePacketFeedResult feed_result =
            OfflinePacketFeed::Run(input_path, output_path, result.config);
        if (!feed_result) {
            std::cerr << "Offline feed error: " << feed_result.error << '\n';
            return 1;
        }

        std::cout << "Offline feed completed.\n"
                  << "input: " << input_path.string() << '\n'
                  << "output: " << output_path.string() << '\n';

        if (result.config.stats.enabled) {
            PrintCaptureStats(std::cout, feed_result.stats);
        }

        return 0;
    }

    return RunLiveCapture(result.config);
}
