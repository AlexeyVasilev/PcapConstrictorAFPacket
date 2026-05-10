#pragma once

#include <cstdint>

namespace pcap_constrictor_afpacket {

struct CaptureStats {
    std::uint64_t packets_total{0};
    std::uint64_t packets_written{0};
    std::uint64_t bytes_input{0};
    std::uint64_t bytes_output{0};
    std::uint64_t bytes_saved{0};
    bool kernel_stats_available{false};
    std::uint64_t kernel_packets{0};
    std::uint64_t kernel_drops{0};
    std::uint64_t receive_errors{0};
    std::uint64_t tls_appdata_constricted{0};
    std::uint64_t tls_fallback{0};
    std::uint64_t quic_long_header{0};
    std::uint64_t quic_short_matched{0};
    std::uint64_t quic_short_constricted{0};
    std::uint64_t quic_fallback{0};
};

}  // namespace pcap_constrictor_afpacket
