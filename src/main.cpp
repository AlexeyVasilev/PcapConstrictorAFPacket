#include <iostream>
#include <string_view>

#include "config/ConfigLoader.hpp"

namespace pcap_constrictor_afpacket {
namespace {

void PrintUsage(std::ostream& output) {
    output << "Usage:\n"
           << "  PcapConstrictorAFPacket --config <config.ini>\n"
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

    if (argc != 3 || std::string_view(argv[1]) != "--config") {
        PrintUsage(std::cerr);
        return 1;
    }

    const ConfigLoadResult result = ConfigLoader::LoadFromFile(argv[2]);
    if (!result) {
        std::cerr << "Configuration error: " << result.error << '\n';
        return 1;
    }

    std::cout << "Configuration loaded from '" << argv[2] << "'.\n"
              << "AF_PACKET live capture is not implemented in this milestone yet.\n";
    return 0;
}
