#include <filesystem>
#include <iostream>
#include <string_view>

#include "config/ConfigLoader.hpp"
#include "offline/OfflinePacketFeed.hpp"

namespace pcap_constrictor_afpacket {
namespace {

void PrintUsage(std::ostream& output) {
    output << "Usage:\n"
           << "  PcapConstrictorAFPacket --config <config.ini>\n"
           << "  PcapConstrictorAFPacket --config <config.ini> --offline-input <input.pcap>\n"
           << "  PcapConstrictorAFPacket --help\n";
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
            std::cout << "packets_total: " << feed_result.stats.packets_total << '\n'
                      << "packets_written: " << feed_result.stats.packets_written << '\n'
                      << "bytes_input: " << feed_result.stats.bytes_input << '\n'
                      << "bytes_output: " << feed_result.stats.bytes_output << '\n'
                      << "bytes_saved: " << feed_result.stats.bytes_saved << '\n';
        }

        return 0;
    }

    std::cout << "Configuration loaded from '" << argv[2] << "'.\n"
              << "AF_PACKET live capture is not implemented in this milestone yet.\n";
    return 0;
}
