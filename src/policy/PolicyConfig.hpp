#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pcap_constrictor_afpacket {

struct PolicyConfig {
    struct CaptureOptions {
        std::uint32_t default_snaplen{65535};
        std::uint32_t max_capture_len{65535};
        std::filesystem::path output{"output.pcap"};
    } capture;

    struct TlsOptions {
        bool enabled{true};
        std::vector<std::uint16_t> ports{443, 8443};
        std::uint32_t app_data_keep_record_bytes{256};
        std::uint32_t app_data_continuation_keep_bytes{64};
    } tls;

    struct QuicOptions {
        bool enabled{true};
        std::vector<std::uint16_t> ports{443};
        std::uint32_t short_header_keep_packet_bytes{128};
        bool require_dcid_match{false};
        bool allow_short_header_without_known_dcid{true};
    } quic;

    struct StatsOptions {
        bool enabled{true};
    } stats;
};

}  // namespace pcap_constrictor_afpacket
