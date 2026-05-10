#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "capture/CapturedPacket.hpp"
#include "writer/PcapWriter.hpp"

namespace {

std::uint16_t ReadLe16(const std::vector<unsigned char>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes.at(offset)) |
           (static_cast<std::uint16_t>(bytes.at(offset + 1)) << 8U);
}

std::uint32_t ReadLe32(const std::vector<unsigned char>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes.at(offset)) |
           (static_cast<std::uint32_t>(bytes.at(offset + 1)) << 8U) |
           (static_cast<std::uint32_t>(bytes.at(offset + 2)) << 16U) |
           (static_cast<std::uint32_t>(bytes.at(offset + 3)) << 24U);
}

int Fail(std::string_view message) {
    std::cerr << "[PcapWriterTests] " << message << '\n';
    return 1;
}

std::filesystem::path MakeTemporaryPcapPath() {
    namespace fs = std::filesystem;

    const auto unique_suffix =
        static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count());
    return fs::temp_directory_path() /
           ("pcap_constrictor_afpacket_writer_test_" + std::to_string(unique_suffix) + ".pcap");
}

void RemoveIfExists(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
}

}  // namespace

int RunPcapWriterTests() {
    namespace fs = std::filesystem;
    using namespace pcap_constrictor_afpacket;

    constexpr std::array<std::byte, 18> frame{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB},
        std::byte{0x08}, std::byte{0x00}, std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2E},
    };

    const fs::path output_path = MakeTemporaryPcapPath();

    {
        std::ofstream output(output_path, std::ios::binary);
        if (!output) {
            return Fail("unable to create temporary output file");
        }

        CapturedPacket packet{
            .packet = PacketView(std::span(frame), static_cast<std::uint32_t>(frame.size()), 64U),
            .timestamp = std::chrono::system_clock::time_point(std::chrono::seconds(1700000000) +
                                                               std::chrono::microseconds(123456)),
            .ifindex = 2,
            .direction = PacketDirection::Incoming,
        };

        PcapWriter writer(output, 512U);
        writer.WritePacket(packet, 18U);
    }

    std::vector<unsigned char> bytes;
    {
        std::ifstream input(output_path, std::ios::binary);
        if (!input) {
            RemoveIfExists(output_path);
            return Fail("unable to reopen written PCAP file");
        }

        bytes.assign(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
    }

    RemoveIfExists(output_path);

    if (bytes.size() != 24U + 16U + frame.size()) {
        return Fail("unexpected PCAP file size");
    }

    if (ReadLe32(bytes, 0) != 0xA1B2C3D4U) {
        return Fail("wrong PCAP magic");
    }
    if (ReadLe16(bytes, 4) != 2U || ReadLe16(bytes, 6) != 4U) {
        return Fail("wrong PCAP version");
    }
    if (ReadLe32(bytes, 16) != 512U) {
        return Fail("wrong PCAP snaplen");
    }
    if (ReadLe32(bytes, 20) != 1U) {
        return Fail("wrong PCAP linktype");
    }
    if (ReadLe32(bytes, 24) != 1700000000U) {
        return Fail("wrong packet timestamp seconds");
    }
    if (ReadLe32(bytes, 28) != 123456U) {
        return Fail("wrong packet timestamp microseconds");
    }
    if (ReadLe32(bytes, 32) != static_cast<std::uint32_t>(frame.size())) {
        return Fail("wrong incl_len");
    }
    if (ReadLe32(bytes, 36) != 64U) {
        return Fail("wrong orig_len");
    }

    for (std::size_t index = 0; index < frame.size(); ++index) {
        if (bytes[40U + index] != std::to_integer<unsigned char>(frame[index])) {
            return Fail("packet payload bytes do not match");
        }
    }

    return 0;
}
