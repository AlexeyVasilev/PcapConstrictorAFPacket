#include "policy/QuicConstrictor.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace pcap_constrictor_afpacket {

namespace {

struct LongHeaderInfo {
    QuicConstrictor::ConnectionId dcid{};
    QuicConstrictor::ConnectionId scid{};
};

bool HasBytes(const std::span<const std::byte> bytes,
              const std::size_t offset,
              const std::size_t count) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

std::uint32_t ReadBe32(const std::span<const std::byte> bytes,
                       const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1U])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2U])) << 8U) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3U]));
}

bool PortConfigured(const std::vector<std::uint16_t>& ports, const std::uint16_t port) noexcept {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

int CompareEndpoints(const QuicConstrictor::Endpoint& left,
                     const QuicConstrictor::Endpoint& right) noexcept {
    const std::size_t compare_length =
        std::min<std::size_t>(left.address_length, right.address_length);
    for (std::size_t index = 0; index < compare_length; ++index) {
        const auto left_byte = std::to_integer<std::uint8_t>(left.address[index]);
        const auto right_byte = std::to_integer<std::uint8_t>(right.address[index]);
        if (left_byte < right_byte) {
            return -1;
        }
        if (left_byte > right_byte) {
            return 1;
        }
    }

    if (left.address_length < right.address_length) {
        return -1;
    }
    if (left.address_length > right.address_length) {
        return 1;
    }
    if (left.port < right.port) {
        return -1;
    }
    if (left.port > right.port) {
        return 1;
    }
    return 0;
}

QuicConstrictor::Endpoint MakeEndpoint(const std::array<std::byte, 16>& address,
                                       const std::uint8_t address_length,
                                       const std::uint16_t port) noexcept {
    return QuicConstrictor::Endpoint{
        .address = address,
        .address_length = address_length,
        .port = port,
    };
}

std::pair<QuicConstrictor::FlowKey, QuicConstrictor::FlowDirection> MakeCanonicalFlow(
    const PacketDecodeResult& decoded) noexcept {
    const auto source = MakeEndpoint(decoded.src_address, decoded.address_length, decoded.src_port);
    const auto destination = MakeEndpoint(decoded.dst_address, decoded.address_length, decoded.dst_port);

    if (CompareEndpoints(source, destination) <= 0) {
        return {
            QuicConstrictor::FlowKey{
                .ip_version = decoded.ip_version,
                .endpoint_a = source,
                .endpoint_b = destination,
            },
            QuicConstrictor::FlowDirection::AToB,
        };
    }

    return {
        QuicConstrictor::FlowKey{
            .ip_version = decoded.ip_version,
            .endpoint_a = destination,
            .endpoint_b = source,
        },
        QuicConstrictor::FlowDirection::BToA,
    };
}

bool ReadConnectionId(const std::span<const std::byte> payload,
                      std::size_t& offset,
                      QuicConstrictor::ConnectionId& out) noexcept {
    if (!HasBytes(payload, offset, 1U)) {
        return false;
    }

    const auto length = std::to_integer<std::uint8_t>(payload[offset++]);
    if (length > QuicConstrictor::kMaxConnectionIdLength ||
        !HasBytes(payload, offset, length)) {
        return false;
    }

    out = {};
    out.length = length;
    out.known = true;
    std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                static_cast<std::ptrdiff_t>(length),
                out.bytes.begin());
    offset += length;
    return true;
}

bool ParseLongHeader(const std::span<const std::byte> payload,
                     LongHeaderInfo& out) noexcept {
    if (!HasBytes(payload, 0U, 7U)) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(payload[0]);
    if ((first_byte & 0x80U) == 0U) {
        return false;
    }

    out = {};
    std::size_t offset = 1U;
    if (!HasBytes(payload, offset, 4U)) {
        return false;
    }

    static_cast<void>(ReadBe32(payload, offset));
    offset += 4U;

    if (!ReadConnectionId(payload, offset, out.dcid) ||
        !ReadConnectionId(payload, offset, out.scid)) {
        return false;
    }

    return true;
}

bool ConnectionIdMatches(const QuicConstrictor::ConnectionId& connection_id,
                         const std::span<const std::byte> payload,
                         const std::size_t offset) noexcept {
    if (!connection_id.known) {
        return false;
    }

    return std::equal(connection_id.bytes.begin(),
                      connection_id.bytes.begin() + connection_id.length,
                      payload.begin() + static_cast<std::ptrdiff_t>(offset));
}

}  // namespace

std::size_t QuicConstrictor::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t hash = static_cast<std::size_t>(1469598103934665603ULL);
    const auto mix = [&hash](const std::uint8_t value) noexcept {
        hash ^= value;
        hash *= static_cast<std::size_t>(1099511628211ULL);
    };

    mix(static_cast<std::uint8_t>(key.ip_version));

    const auto mix_endpoint = [&mix](const Endpoint& endpoint) noexcept {
        mix(endpoint.address_length);
        for (std::size_t index = 0; index < endpoint.address_length; ++index) {
            mix(std::to_integer<std::uint8_t>(endpoint.address[index]));
        }
        mix(static_cast<std::uint8_t>(endpoint.port >> 8U));
        mix(static_cast<std::uint8_t>(endpoint.port & 0x00FFU));
    };

    mix_endpoint(key.endpoint_a);
    mix_endpoint(key.endpoint_b);
    return hash;
}

QuicConstrictResult QuicConstrictor::Evaluate(std::span<const std::byte> packet,
                                              const PacketDecodeResult& decoded,
                                              const PolicyConfig::QuicOptions& config) noexcept {
    if (!config.enabled ||
        decoded.transport_protocol != TransportProtocol::Udp ||
        decoded.transport_payload_length == 0U ||
        (!PortConfigured(config.ports, decoded.src_port) &&
         !PortConfigured(config.ports, decoded.dst_port))) {
        return {};
    }

    if (decoded.transport_payload_offset > packet.size() ||
        decoded.transport_payload_length > packet.size() - decoded.transport_payload_offset) {
        return {.disposition = QuicConstrictDisposition::MalformedFallback};
    }

    const auto payload = packet.subspan(decoded.transport_payload_offset, decoded.transport_payload_length);
    if (payload.empty()) {
        return {};
    }

    const auto [flow_key, direction] = MakeCanonicalFlow(decoded);
    const auto first_byte = std::to_integer<std::uint8_t>(payload[0]);

    if ((first_byte & 0x80U) != 0U) {
        LongHeaderInfo long_header{};
        if (!ParseLongHeader(payload, long_header)) {
            return {.disposition = QuicConstrictDisposition::MalformedFallback};
        }

        auto& flow_state = flow_states_[flow_key];
        if (direction == FlowDirection::AToB) {
            flow_state.endpoint_a_scid = long_header.scid;
        } else {
            flow_state.endpoint_b_scid = long_header.scid;
        }

        return {.disposition = QuicConstrictDisposition::LongHeader};
    }

    const auto found = flow_states_.find(flow_key);
    const ConnectionId* expected_dcid =
        found == flow_states_.end()
            ? nullptr
            : (direction == FlowDirection::AToB
                   ? &found->second.endpoint_b_scid
                   : &found->second.endpoint_a_scid);

    if (expected_dcid == nullptr || !expected_dcid->known) {
        if (config.require_dcid_match || !config.allow_short_header_without_known_dcid) {
            return {.disposition = QuicConstrictDisposition::UnknownCidFallback};
        }

        const std::size_t keep_payload_bytes =
            std::max<std::size_t>(config.short_header_keep_packet_bytes, 1U);
        return {
            .disposition = QuicConstrictDisposition::ShortHeaderMatched,
            .output_len = static_cast<std::uint32_t>(
                decoded.transport_payload_offset +
                std::min<std::size_t>(payload.size(), keep_payload_bytes)),
        };
    }

    const std::size_t required_prefix_bytes = 1U + expected_dcid->length;
    if (!HasBytes(payload, 0U, required_prefix_bytes)) {
        return {.disposition = QuicConstrictDisposition::MalformedFallback};
    }

    if (!ConnectionIdMatches(*expected_dcid, payload, 1U)) {
        return {.disposition = QuicConstrictDisposition::DcidMismatchFallback};
    }

    const std::size_t keep_payload_bytes =
        std::max<std::size_t>(config.short_header_keep_packet_bytes, required_prefix_bytes);
    return {
        .disposition = QuicConstrictDisposition::ShortHeaderMatched,
        .output_len = static_cast<std::uint32_t>(
            decoded.transport_payload_offset +
            std::min<std::size_t>(payload.size(), keep_payload_bytes)),
    };
}

}  // namespace pcap_constrictor_afpacket
