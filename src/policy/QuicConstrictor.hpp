#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>

#include "decode/PacketDecode.hpp"
#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

enum class QuicConstrictDisposition {
    NotApplicable,
    LongHeader,
    ShortHeaderMatched,
    UnknownCidFallback,
    DcidMismatchFallback,
    MalformedFallback,
};

struct QuicConstrictResult {
    QuicConstrictDisposition disposition{QuicConstrictDisposition::NotApplicable};
    std::uint32_t output_len{0};
};

class QuicConstrictor {
public:
    [[nodiscard]] QuicConstrictResult Evaluate(std::span<const std::byte> packet,
                                               const PacketDecodeResult& decoded,
                                               const PolicyConfig::QuicOptions& config) noexcept;

    static constexpr std::size_t kMaxConnectionIdLength = 20U;

    struct ConnectionId {
        std::array<std::byte, kMaxConnectionIdLength> bytes{};
        std::uint8_t length{0};
        bool known{false};

        [[nodiscard]] bool operator==(const ConnectionId& other) const noexcept = default;
    };

    struct Endpoint {
        std::array<std::byte, 16> address{};
        std::uint8_t address_length{0};
        std::uint16_t port{0};

        [[nodiscard]] bool operator==(const Endpoint& other) const noexcept = default;
    };

    struct FlowKey {
        IpVersion ip_version{IpVersion::None};
        Endpoint endpoint_a{};
        Endpoint endpoint_b{};

        [[nodiscard]] bool operator==(const FlowKey& other) const noexcept = default;
    };

    struct FlowKeyHash {
        [[nodiscard]] std::size_t operator()(const FlowKey& key) const noexcept;
    };

    enum class FlowDirection {
        AToB,
        BToA,
    };

    struct FlowState {
        ConnectionId endpoint_a_scid{};
        ConnectionId endpoint_b_scid{};
    };

private:
    std::unordered_map<FlowKey, FlowState, FlowKeyHash> flow_states_{};
};

}  // namespace pcap_constrictor_afpacket
