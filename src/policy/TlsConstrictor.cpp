#include "policy/TlsConstrictor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace pcap_constrictor_afpacket {

namespace {

constexpr std::uint8_t kTlsChangeCipherSpec = 0x14U;
constexpr std::uint8_t kTlsAlert = 0x15U;
constexpr std::uint8_t kTlsHandshake = 0x16U;
constexpr std::uint8_t kTlsApplicationData = 0x17U;
constexpr std::size_t kTlsRecordHeaderSize = 5U;
constexpr std::uint8_t kTcpFlagSyn = 0x02U;
constexpr std::uint8_t kTcpFlagRst = 0x04U;

bool HasBytes(const std::span<const std::byte> bytes,
              const std::size_t offset,
              const std::size_t count) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

bool IsTlsContentType(const std::uint8_t content_type) noexcept {
    return content_type == kTlsChangeCipherSpec ||
           content_type == kTlsAlert ||
           content_type == kTlsHandshake ||
           content_type == kTlsApplicationData;
}

std::uint16_t ReadBe16(const std::span<const std::byte> bytes,
                       const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 8U |
           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1U]));
}

bool ReadTlsRecordHeader(const std::span<const std::byte> payload,
                         const std::size_t offset,
                         std::uint8_t& content_type,
                         std::uint16_t& record_length) noexcept {
    if (!HasBytes(payload, offset, kTlsRecordHeaderSize)) {
        return false;
    }

    content_type = std::to_integer<std::uint8_t>(payload[offset]);
    if (!IsTlsContentType(content_type) ||
        std::to_integer<std::uint8_t>(payload[offset + 1U]) != 0x03U) {
        return false;
    }

    record_length = ReadBe16(payload, offset + 3U);
    return true;
}

std::uint32_t AdvanceTcpSeq(const std::uint32_t seq, const std::size_t payload_size) noexcept {
    return seq + static_cast<std::uint32_t>(payload_size);
}

std::size_t ClampedKeepSize(const std::uint32_t configured, const std::size_t available) noexcept {
    return std::min(static_cast<std::size_t>(configured), available);
}

TlsConstrictor::DirectionKey MakeDirectionKey(const PacketDecodeResult& decoded) noexcept {
    return TlsConstrictor::DirectionKey{
        .src_ip = decoded.src_address,
        .dst_ip = decoded.dst_address,
        .address_length = decoded.address_length,
        .src_port = decoded.src_port,
        .dst_port = decoded.dst_port,
    };
}

}  // namespace

std::size_t TlsConstrictor::DirectionKeyHash::operator()(const DirectionKey& key) const noexcept {
    std::size_t hash = static_cast<std::size_t>(1469598103934665603ULL);
    const auto mix = [&hash](const std::uint8_t value) noexcept {
        hash ^= value;
        hash *= static_cast<std::size_t>(1099511628211ULL);
    };

    mix(key.address_length);
    for (std::size_t index = 0; index < key.address_length; ++index) {
        mix(std::to_integer<std::uint8_t>(key.src_ip[index]));
    }
    for (std::size_t index = 0; index < key.address_length; ++index) {
        mix(std::to_integer<std::uint8_t>(key.dst_ip[index]));
    }
    mix(static_cast<std::uint8_t>(key.src_port >> 8U));
    mix(static_cast<std::uint8_t>(key.src_port & 0x00FFU));
    mix(static_cast<std::uint8_t>(key.dst_port >> 8U));
    mix(static_cast<std::uint8_t>(key.dst_port & 0x00FFU));
    return hash;
}

TlsConstrictResult TlsConstrictor::Evaluate(const std::span<const std::byte> packet,
                                            const PacketDecodeResult& decoded,
                                            const PolicyConfig::TlsOptions& config) noexcept {
    TlsConstrictResult result{
        .disposition = TlsConstrictDisposition::NoRecord,
        .output_len = static_cast<std::uint32_t>(packet.size()),
    };

    if (decoded.transport_protocol != TransportProtocol::Tcp) {
        result.disposition = TlsConstrictDisposition::Malformed;
        return result;
    }

    const DirectionKey key = MakeDirectionKey(decoded);
    const DirectionKey reverse_key{
        .src_ip = decoded.dst_address,
        .dst_ip = decoded.src_address,
        .address_length = decoded.address_length,
        .src_port = decoded.dst_port,
        .dst_port = decoded.src_port,
    };

    if ((decoded.tcp_flags & (kTcpFlagSyn | kTcpFlagRst)) != 0U) {
        directions_.erase(key);
        directions_.erase(reverse_key);
    }

    if (decoded.transport_payload_length == 0U) {
        result.disposition = TlsConstrictDisposition::NoApplicationData;
        return result;
    }

    if (!HasBytes(packet, decoded.transport_payload_offset, decoded.transport_payload_length)) {
        result.disposition = TlsConstrictDisposition::Malformed;
        return result;
    }

    auto& state = directions_[key];
    const bool confirmed_tls = state.confirmed_tls;
    const auto payload =
        packet.subspan(decoded.transport_payload_offset, decoded.transport_payload_length);

    auto clear_active_record = [&state]() noexcept {
        state.has_active_record = false;
        state.active_record_constrictible = false;
        state.active_record_content_type = 0U;
        state.active_record_remaining_bytes = 0U;
    };

    if (state.synchronized && decoded.tcp_seq != state.expected_tcp_seq) {
        clear_active_record();
        state.synchronized = false;
        state.expected_tcp_seq = 0U;
    }

    std::size_t payload_offset = 0U;
    std::size_t candidate_payload_size = decoded.transport_payload_length;
    bool has_candidate = false;
    bool uncertain = false;
    bool reset_direction = false;
    bool kept_middle_continuation = false;

    if (state.has_active_record) {
        const std::size_t remaining_record_bytes =
            static_cast<std::size_t>(state.active_record_remaining_bytes);
        if (remaining_record_bytes > payload.size()) {
            if (state.active_record_constrictible) {
                kept_middle_continuation = true;
            }
            state.active_record_remaining_bytes -= static_cast<std::uint32_t>(payload.size());
            payload_offset = payload.size();
        } else if (remaining_record_bytes == payload.size()) {
            if (state.active_record_constrictible) {
                candidate_payload_size = ClampedKeepSize(
                    config.app_data_continuation_keep_bytes,
                    payload.size());
                has_candidate = true;
            }
            payload_offset = payload.size();
            clear_active_record();
        } else {
            payload_offset = remaining_record_bytes;
            if (state.active_record_constrictible) {
                clear_active_record();
                reset_direction = true;
            } else {
                clear_active_record();
            }
        }
    }

    while (!uncertain && !reset_direction && payload_offset < payload.size()) {
        std::uint8_t content_type = 0U;
        std::uint16_t record_length = 0U;
        if (!ReadTlsRecordHeader(payload, payload_offset, content_type, record_length)) {
            if (!state.synchronized) {
                if (!confirmed_tls) {
                    directions_.erase(key);
                }
                result.disposition = TlsConstrictDisposition::NoRecord;
                return result;
            }
            uncertain = true;
            break;
        }

        if (!state.synchronized && content_type != kTlsHandshake && !confirmed_tls) {
            directions_.erase(key);
            result.disposition = TlsConstrictDisposition::NoRecord;
            return result;
        }

        state.synchronized = true;
        if (content_type == kTlsHandshake) {
            state.confirmed_tls = true;
            directions_[reverse_key].confirmed_tls = true;
        }

        const std::size_t record_total_size =
            kTlsRecordHeaderSize + static_cast<std::size_t>(record_length);
        const std::size_t remaining_payload = payload.size() - payload_offset;
        const bool is_app_data = content_type == kTlsApplicationData;

        if (record_total_size > remaining_payload) {
            if (is_app_data) {
                state.has_seen_application_data = true;
                candidate_payload_size = payload_offset + ClampedKeepSize(
                    config.app_data_keep_record_bytes,
                    remaining_payload);
                has_candidate = true;
            }

            state.has_active_record = true;
            state.active_record_content_type = content_type;
            state.active_record_remaining_bytes =
                static_cast<std::uint32_t>(record_total_size - remaining_payload);
            state.active_record_constrictible = is_app_data;
            payload_offset = payload.size();
            break;
        }

        if (is_app_data) {
            state.has_seen_application_data = true;
            candidate_payload_size = payload_offset + ClampedKeepSize(
                config.app_data_keep_record_bytes,
                record_total_size);
            has_candidate = true;
        }

        payload_offset += record_total_size;
    }

    state.expected_tcp_seq = AdvanceTcpSeq(decoded.tcp_seq, decoded.transport_payload_length);

    if (reset_direction) {
        const bool was_confirmed_tls = state.confirmed_tls;
        const bool had_seen_application_data = state.has_seen_application_data;
        directions_.erase(key);
        if (was_confirmed_tls) {
            directions_[key].confirmed_tls = true;
            directions_[key].has_seen_application_data = had_seen_application_data;
        }
        result.disposition = TlsConstrictDisposition::NoApplicationData;
        return result;
    }

    if (uncertain) {
        result.disposition = TlsConstrictDisposition::Malformed;
        return result;
    }

    if (kept_middle_continuation) {
        result.disposition = TlsConstrictDisposition::NoApplicationData;
        return result;
    }

    if (!state.synchronized || !has_candidate || candidate_payload_size >= decoded.transport_payload_length) {
        result.disposition = state.synchronized
                                 ? TlsConstrictDisposition::NoApplicationData
                                 : TlsConstrictDisposition::NoRecord;
        return result;
    }

    result.disposition = TlsConstrictDisposition::AppDataPrefix;
    result.output_len = static_cast<std::uint32_t>(decoded.transport_payload_offset + candidate_payload_size);
    return result;
}

}  // namespace pcap_constrictor_afpacket
