#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>

#include "decode/PacketDecode.hpp"
#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

enum class TlsConstrictDisposition {
    NoRecord,
    Malformed,
    NoApplicationData,
    AppDataPrefix,
    UncertainFallback,
};

struct TlsConstrictResult {
    TlsConstrictDisposition disposition{TlsConstrictDisposition::NoRecord};
    std::uint32_t output_len{0};
};

class TlsConstrictor {
public:
    [[nodiscard]] TlsConstrictResult Evaluate(std::span<const std::byte> packet,
                                              const PacketDecodeResult& decoded,
                                              const PolicyConfig::TlsOptions& config) noexcept;

    struct DirectionKey {
        std::array<std::byte, 16> src_ip{};
        std::array<std::byte, 16> dst_ip{};
        std::uint8_t address_length{0};
        std::uint16_t src_port{0};
        std::uint16_t dst_port{0};

        [[nodiscard]] bool operator==(const DirectionKey& other) const noexcept = default;
    };

    struct DirectionKeyHash {
        [[nodiscard]] std::size_t operator()(const DirectionKey& key) const noexcept;
    };

    struct DirectionState {
        bool synchronized{false};
        std::uint32_t expected_tcp_seq{0};
        bool has_active_record{false};
        std::uint32_t active_record_remaining_bytes{0};
        bool active_record_constrictible{false};
    };

private:
    std::unordered_map<DirectionKey, DirectionState, DirectionKeyHash> directions_{};
};

}  // namespace pcap_constrictor_afpacket
