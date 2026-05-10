#pragma once

#include <cstdint>

namespace pcap_constrictor_afpacket {

struct CaptureStats {
    std::uint64_t packets_total{0};
    std::uint64_t packets_written{0};
    std::uint64_t bytes_input{0};
    std::uint64_t bytes_output{0};
    std::uint64_t bytes_saved{0};
};

}  // namespace pcap_constrictor_afpacket
