#pragma once

#include <cstdint>

namespace pcap_constrictor_afpacket {

struct CaptureStats {
    std::uint64_t packets_seen{0};
    std::uint64_t packets_written{0};
    std::uint64_t bytes_seen{0};
    std::uint64_t bytes_written{0};
};

}  // namespace pcap_constrictor_afpacket
