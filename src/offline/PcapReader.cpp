#include "offline/PcapReader.hpp"

#include <array>
#include <limits>
#include <span>
#include <sstream>
#include <system_error>
#include <utility>

namespace pcap_constrictor_afpacket {

namespace {

bool ReadExact(std::ifstream& stream, std::span<std::byte> out) {
    if (out.empty()) {
        return true;
    }

    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return stream.gcount() == static_cast<std::streamsize>(out.size());
}

std::uint16_t ReadU16(const std::uint8_t* bytes, PcapEndianness endianness) {
    if (endianness == PcapEndianness::Little) {
        return static_cast<std::uint16_t>(bytes[0]) |
               (static_cast<std::uint16_t>(bytes[1]) << 8U);
    }

    return (static_cast<std::uint16_t>(bytes[0]) << 8U) |
           static_cast<std::uint16_t>(bytes[1]);
}

std::uint32_t ReadU32(const std::uint8_t* bytes, PcapEndianness endianness) {
    if (endianness == PcapEndianness::Little) {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8U) |
               (static_cast<std::uint32_t>(bytes[2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }

    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

bool DetectMagic(const std::array<std::uint8_t, 4>& magic_bytes,
                 PcapEndianness& endianness,
                 PcapTimePrecision& precision) noexcept {
    if (magic_bytes == std::array<std::uint8_t, 4>{0xd4U, 0xc3U, 0xb2U, 0xa1U}) {
        endianness = PcapEndianness::Little;
        precision = PcapTimePrecision::Microsecond;
        return true;
    }

    if (magic_bytes == std::array<std::uint8_t, 4>{0xa1U, 0xb2U, 0xc3U, 0xd4U}) {
        endianness = PcapEndianness::Big;
        precision = PcapTimePrecision::Microsecond;
        return true;
    }

    if (magic_bytes == std::array<std::uint8_t, 4>{0x4dU, 0x3cU, 0xb2U, 0xa1U}) {
        endianness = PcapEndianness::Little;
        precision = PcapTimePrecision::Nanosecond;
        return true;
    }

    if (magic_bytes == std::array<std::uint8_t, 4>{0xa1U, 0xb2U, 0x3cU, 0x4dU}) {
        endianness = PcapEndianness::Big;
        precision = PcapTimePrecision::Nanosecond;
        return true;
    }

    return false;
}

std::string PacketErrorPrefix(std::uint64_t packet_index, std::uint64_t offset) {
    std::ostringstream out;
    out << "packet " << packet_index << " at file offset " << offset << ": ";
    return out.str();
}

}  // namespace

std::chrono::system_clock::time_point PcapPacketRecord::timestamp(
    const PcapTimePrecision precision) const noexcept {
    const auto seconds = std::chrono::seconds(ts_sec);
    if (precision == PcapTimePrecision::Nanosecond) {
        return std::chrono::system_clock::time_point(seconds + std::chrono::nanoseconds(ts_fraction));
    }

    return std::chrono::system_clock::time_point(seconds + std::chrono::microseconds(ts_fraction));
}

void PcapReader::Clear() {
    if (stream_.is_open()) {
        stream_.close();
    }

    global_header_ = {};
    file_size_ = 0;
    next_input_offset_ = 0;
    next_packet_index_ = 0;
    has_error_ = false;
    error_message_.clear();
    incomplete_tail_info_.reset();
}

void PcapReader::SetError(std::string message) {
    has_error_ = true;
    error_message_ = std::move(message);
}

void PcapReader::SetErrorAt(const std::uint64_t offset, std::string message) {
    std::ostringstream out;
    out << "file offset " << offset << ": " << message;
    SetError(out.str());
}

bool PcapReader::Open(const std::filesystem::path& path) {
    Clear();

    std::error_code size_error;
    const auto size = std::filesystem::file_size(path, size_error);
    if (size_error) {
        SetError("failed to read input file size");
        return false;
    }

    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::uint64_t>::max())) {
        SetError("input file is too large");
        return false;
    }
    file_size_ = static_cast<std::uint64_t>(size);

    stream_ = std::ifstream(path, std::ios::binary);
    if (!stream_.is_open()) {
        SetError("failed to open input file");
        return false;
    }

    std::array<std::byte, kClassicPcapGlobalHeaderSize> header_bytes{};
    if (!ReadExact(stream_, std::span<std::byte>(header_bytes.data(), header_bytes.size()))) {
        SetErrorAt(0, "unexpected EOF while reading PCAP global header");
        stream_.close();
        return false;
    }

    std::array<std::uint8_t, 4> magic_bytes{
        std::to_integer<std::uint8_t>(header_bytes[0]),
        std::to_integer<std::uint8_t>(header_bytes[1]),
        std::to_integer<std::uint8_t>(header_bytes[2]),
        std::to_integer<std::uint8_t>(header_bytes[3]),
    };

    if (ReadU32(magic_bytes.data(), PcapEndianness::Big) == kPcapNgSectionHeaderBlockType) {
        SetErrorAt(0, "pcapng is not supported by this offline feed mode");
        stream_.close();
        return false;
    }

    PcapEndianness endianness = PcapEndianness::Little;
    PcapTimePrecision precision = PcapTimePrecision::Microsecond;
    if (!DetectMagic(magic_bytes, endianness, precision)) {
        SetErrorAt(0, "unsupported classic PCAP magic number");
        stream_.close();
        return false;
    }

    const auto* raw = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
    global_header_.magic_bytes = magic_bytes;
    global_header_.endianness = endianness;
    global_header_.time_precision = precision;
    global_header_.version_major = ReadU16(raw + 4U, endianness);
    global_header_.version_minor = ReadU16(raw + 6U, endianness);
    global_header_.reserved1 = ReadU32(raw + 8U, endianness);
    global_header_.reserved2 = ReadU32(raw + 12U, endianness);
    global_header_.snaplen = ReadU32(raw + 16U, endianness);
    global_header_.link_type = ReadU32(raw + 20U, endianness);

    if (global_header_.version_major != 2U || global_header_.version_minor != 4U) {
        std::ostringstream out;
        out << "unsupported classic PCAP version "
            << global_header_.version_major << "." << global_header_.version_minor;
        SetErrorAt(4U, out.str());
        stream_.close();
        return false;
    }

    if (global_header_.snaplen == 0U) {
        SetErrorAt(16U, "invalid PCAP snaplen 0");
        stream_.close();
        return false;
    }

    if (global_header_.link_type != kEthernetLinkType) {
        std::ostringstream out;
        out << "unsupported linktype " << global_header_.link_type
            << "; only Ethernet (DLT_EN10MB/1) is supported";
        SetErrorAt(20U, out.str());
        stream_.close();
        return false;
    }

    next_input_offset_ = kClassicPcapGlobalHeaderSize;
    return true;
}

std::optional<PcapPacketRecord> PcapReader::ReadNext() {
    if (!stream_.is_open() || has_error_) {
        return std::nullopt;
    }

    if (next_input_offset_ == file_size_) {
        return std::nullopt;
    }

    if (next_input_offset_ > file_size_) {
        SetErrorAt(next_input_offset_, "reader offset is past end of input file");
        return std::nullopt;
    }

    const auto remaining_for_header = file_size_ - next_input_offset_;
    if (remaining_for_header < kClassicPcapPacketHeaderSize) {
        std::ostringstream out;
        out << "unexpected EOF while reading packet header; "
            << remaining_for_header << " trailing byte(s) could not be processed";
        SetErrorAt(next_input_offset_, out.str());
        incomplete_tail_info_ = PcapIncompleteTailInfo{
            .kind = PcapIncompleteTailKind::PacketHeader,
            .file_offset = next_input_offset_,
            .trailing_bytes = remaining_for_header,
        };
        return std::nullopt;
    }

    const auto packet_header_offset = next_input_offset_;
    std::array<std::byte, kClassicPcapPacketHeaderSize> header_bytes{};
    if (!ReadExact(stream_, std::span<std::byte>(header_bytes.data(), header_bytes.size()))) {
        SetErrorAt(packet_header_offset, "unexpected EOF while reading packet header");
        return std::nullopt;
    }

    const auto* raw = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
    const auto ts_sec = ReadU32(raw + 0U, global_header_.endianness);
    const auto ts_fraction = ReadU32(raw + 4U, global_header_.endianness);
    const auto captured_length = ReadU32(raw + 8U, global_header_.endianness);
    const auto original_length = ReadU32(raw + 12U, global_header_.endianness);

    if (captured_length > original_length) {
        std::ostringstream out;
        out << PacketErrorPrefix(next_packet_index_, packet_header_offset)
            << "captured length " << captured_length
            << " exceeds original length " << original_length;
        SetError(out.str());
        return std::nullopt;
    }

    const auto data_offset = packet_header_offset + kClassicPcapPacketHeaderSize;
    const auto remaining_data = file_size_ - data_offset;
    if (static_cast<std::uint64_t>(captured_length) > remaining_data) {
        std::ostringstream out;
        out << PacketErrorPrefix(next_packet_index_, packet_header_offset)
            << "unexpected EOF while reading packet payload; expected " << captured_length
            << " byte(s), available " << remaining_data
            << " byte(s), missing "
            << (static_cast<std::uint64_t>(captured_length) - remaining_data)
            << " byte(s)";
        SetError(out.str());
        incomplete_tail_info_ = PcapIncompleteTailInfo{
            .kind = PcapIncompleteTailKind::PacketData,
            .file_offset = data_offset,
            .expected_captured_length = captured_length,
            .available_payload_bytes = remaining_data,
            .missing_payload_bytes = static_cast<std::uint64_t>(captured_length) - remaining_data,
        };
        return std::nullopt;
    }

    std::vector<std::byte> bytes(captured_length);
    if (!ReadExact(stream_, std::span<std::byte>(bytes.data(), bytes.size()))) {
        std::ostringstream out;
        out << PacketErrorPrefix(next_packet_index_, data_offset)
            << "unexpected EOF while reading packet data";
        SetError(out.str());
        return std::nullopt;
    }

    PcapPacketRecord packet{
        .packet_index = next_packet_index_,
        .header_offset = packet_header_offset,
        .data_offset = data_offset,
        .ts_sec = ts_sec,
        .ts_fraction = ts_fraction,
        .captured_length = captured_length,
        .original_length = original_length,
        .bytes = std::move(bytes),
    };

    next_input_offset_ = data_offset + captured_length;
    ++next_packet_index_;
    return packet;
}

bool PcapReader::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapReader::has_error() const noexcept {
    return has_error_;
}

const std::string& PcapReader::error_message() const noexcept {
    return error_message_;
}

const ClassicPcapGlobalHeader& PcapReader::global_header() const noexcept {
    return global_header_;
}

std::uint64_t PcapReader::packet_index() const noexcept {
    return next_packet_index_;
}

const std::optional<PcapIncompleteTailInfo>& PcapReader::incomplete_tail_info() const noexcept {
    return incomplete_tail_info_;
}

}  // namespace pcap_constrictor_afpacket
