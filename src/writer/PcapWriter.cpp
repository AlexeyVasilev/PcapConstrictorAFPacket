#include "writer/PcapWriter.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <stdexcept>

namespace pcap_constrictor_afpacket {

namespace {

void WriteBytes(std::ostream& output, const void* data, std::size_t size) {
    output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!output) {
        throw std::runtime_error("failed to write PCAP data");
    }
}

}  // namespace

PcapWriter::PcapWriter(std::ostream& output, std::uint32_t snaplen) noexcept
    : output_(output),
      snaplen_(snaplen) {}

void PcapWriter::WriteGlobalHeader() {
    if (global_header_written_) {
        return;
    }

    WriteLe32(0xA1B2C3D4U);
    WriteLe16(2);
    WriteLe16(4);
    WriteLe32(0);
    WriteLe32(0);
    WriteLe32(snaplen_);
    WriteLe32(kEthernetLinkType);

    global_header_written_ = true;
}

void PcapWriter::WritePacket(const CapturedPacket& packet) {
    WritePacket(packet, packet.packet.safe_captured_len());
}

void PcapWriter::WritePacket(const CapturedPacket& packet, std::uint32_t incl_len) {
    const std::uint32_t safe_captured_len = packet.packet.safe_captured_len();
    if (incl_len > safe_captured_len) {
        throw std::invalid_argument("incl_len exceeds available packet bytes");
    }

    WriteGlobalHeader();

    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
        packet.timestamp.time_since_epoch());
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(micros);
    const std::uint32_t ts_sec = static_cast<std::uint32_t>(seconds.count());
    const std::uint32_t ts_usec =
        static_cast<std::uint32_t>((micros - seconds).count());
    const std::uint32_t orig_len = std::max(packet.original_len(), incl_len);

    WriteLe32(ts_sec);
    WriteLe32(ts_usec);
    WriteLe32(incl_len);
    WriteLe32(orig_len);
    WriteBytes(output_, packet.data().data(), incl_len);
}

void PcapWriter::WriteLe16(std::uint16_t value) {
    const std::array<std::byte, 2> bytes{
        static_cast<std::byte>(value & 0xFFU),
        static_cast<std::byte>((value >> 8U) & 0xFFU),
    };
    WriteBytes(output_, bytes.data(), bytes.size());
}

void PcapWriter::WriteLe32(std::uint32_t value) {
    const std::array<std::byte, 4> bytes{
        static_cast<std::byte>(value & 0xFFU),
        static_cast<std::byte>((value >> 8U) & 0xFFU),
        static_cast<std::byte>((value >> 16U) & 0xFFU),
        static_cast<std::byte>((value >> 24U) & 0xFFU),
    };
    WriteBytes(output_, bytes.data(), bytes.size());
}

}  // namespace pcap_constrictor_afpacket
