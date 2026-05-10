#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace pcap_constrictor_afpacket {

inline constexpr std::size_t kClassicPcapGlobalHeaderSize = 24U;
inline constexpr std::size_t kClassicPcapPacketHeaderSize = 16U;
inline constexpr std::uint32_t kPcapNgSectionHeaderBlockType = 0x0A0D0D0AU;
inline constexpr std::uint32_t kEthernetLinkType = 1U;

enum class PcapEndianness {
    Little,
    Big,
};

enum class PcapTimePrecision {
    Microsecond,
    Nanosecond,
};

struct ClassicPcapGlobalHeader {
    std::array<std::uint8_t, 4> magic_bytes{};
    PcapEndianness endianness{PcapEndianness::Little};
    PcapTimePrecision time_precision{PcapTimePrecision::Microsecond};
    std::uint16_t version_major{0};
    std::uint16_t version_minor{0};
    std::uint32_t reserved1{0};
    std::uint32_t reserved2{0};
    std::uint32_t snaplen{0};
    std::uint32_t link_type{0};
};

struct PcapPacketRecord {
    std::uint64_t packet_index{0};
    std::uint64_t header_offset{0};
    std::uint64_t data_offset{0};
    std::uint32_t ts_sec{0};
    std::uint32_t ts_fraction{0};
    std::uint32_t captured_length{0};
    std::uint32_t original_length{0};
    std::vector<std::byte> bytes{};

    [[nodiscard]] std::chrono::system_clock::time_point timestamp(
        PcapTimePrecision precision) const noexcept;
};

enum class PcapIncompleteTailKind {
    PacketHeader,
    PacketData,
};

struct PcapIncompleteTailInfo {
    PcapIncompleteTailKind kind{PcapIncompleteTailKind::PacketHeader};
    std::uint64_t file_offset{0};
    std::uint64_t trailing_bytes{0};
    std::uint64_t expected_captured_length{0};
    std::uint64_t available_payload_bytes{0};
    std::uint64_t missing_payload_bytes{0};
};

class PcapReader {
public:
    [[nodiscard]] bool Open(const std::filesystem::path& path);
    [[nodiscard]] std::optional<PcapPacketRecord> ReadNext();

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;
    [[nodiscard]] const ClassicPcapGlobalHeader& global_header() const noexcept;
    [[nodiscard]] std::uint64_t packet_index() const noexcept;
    [[nodiscard]] const std::optional<PcapIncompleteTailInfo>& incomplete_tail_info() const noexcept;

private:
    void Clear();
    void SetError(std::string message);
    void SetErrorAt(std::uint64_t offset, std::string message);

    std::ifstream stream_{};
    ClassicPcapGlobalHeader global_header_{};
    std::uint64_t file_size_{0};
    std::uint64_t next_input_offset_{0};
    std::uint64_t next_packet_index_{0};
    bool has_error_{false};
    std::string error_message_{};
    std::optional<PcapIncompleteTailInfo> incomplete_tail_info_{};
};

}  // namespace pcap_constrictor_afpacket
