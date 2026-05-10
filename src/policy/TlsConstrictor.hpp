#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

enum class TlsConstrictDisposition {
    NoRecord,
    Malformed,
    NoApplicationData,
    AppDataPrefix,
};

struct TlsConstrictResult {
    TlsConstrictDisposition disposition{TlsConstrictDisposition::NoRecord};
    std::uint32_t output_len{0};
};

class TlsConstrictor {
public:
    static TlsConstrictResult Evaluate(std::span<const std::byte> packet,
                                       std::size_t tcp_payload_offset,
                                       std::size_t tcp_payload_length,
                                       const PolicyConfig::TlsOptions& config) noexcept;
};

}  // namespace pcap_constrictor_afpacket
