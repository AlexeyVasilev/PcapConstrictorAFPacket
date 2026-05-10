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

bool LooksLikeTruncatedTlsHeaderPrefix(const std::span<const std::byte> payload,
                                       const std::size_t offset) noexcept {
    const std::size_t remaining = payload.size() - offset;
    if (remaining == 0U || remaining >= kTlsRecordHeaderSize) {
        return false;
    }

    const std::uint8_t content_type = std::to_integer<std::uint8_t>(payload[offset]);
    if (!IsTlsContentType(content_type)) {
        return false;
    }

    if (remaining >= 2U &&
        std::to_integer<std::uint8_t>(payload[offset + 1U]) != 0x03U) {
        return false;
    }

    return true;
}

}  // namespace

TlsConstrictResult TlsConstrictor::Evaluate(const std::span<const std::byte> packet,
                                            const std::size_t tcp_payload_offset,
                                            const std::size_t tcp_payload_length,
                                            const PolicyConfig::TlsOptions& config) noexcept {
    TlsConstrictResult result{
        .disposition = TlsConstrictDisposition::NoRecord,
        .output_len = static_cast<std::uint32_t>(packet.size()),
    };

    if (!HasBytes(packet, tcp_payload_offset, tcp_payload_length)) {
        result.disposition = TlsConstrictDisposition::Malformed;
        return result;
    }

    const std::span<const std::byte> payload =
        packet.subspan(tcp_payload_offset, tcp_payload_length);
    if (payload.empty()) {
        result.disposition = TlsConstrictDisposition::NoApplicationData;
        return result;
    }

    std::size_t record_offset = 0;
    bool saw_valid_record = false;

    while (record_offset < payload.size()) {
        std::uint8_t content_type = 0;
        std::uint16_t record_length = 0;
        if (!ReadTlsRecordHeader(payload, record_offset, content_type, record_length)) {
            result.disposition =
                (saw_valid_record || LooksLikeTruncatedTlsHeaderPrefix(payload, record_offset))
                    ? TlsConstrictDisposition::Malformed
                    : TlsConstrictDisposition::NoRecord;
            return result;
        }

        saw_valid_record = true;
        const std::size_t record_total_size =
            kTlsRecordHeaderSize + static_cast<std::size_t>(record_length);
        if (!HasBytes(payload, record_offset, record_total_size)) {
            result.disposition = TlsConstrictDisposition::Malformed;
            return result;
        }

        if (content_type == kTlsApplicationData) {
            const std::size_t kept_payload_size =
                std::min<std::size_t>(record_length, config.app_data_keep_record_bytes);
            result.disposition = TlsConstrictDisposition::AppDataPrefix;
            result.output_len = static_cast<std::uint32_t>(
                tcp_payload_offset + record_offset + kTlsRecordHeaderSize + kept_payload_size);
            return result;
        }

        record_offset += record_total_size;
    }

    result.disposition = TlsConstrictDisposition::NoApplicationData;
    return result;
}

}  // namespace pcap_constrictor_afpacket
