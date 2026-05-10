#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "capture/CapturedPacket.hpp"
#include "offline/PcapReader.hpp"
#include "writer/PcapWriter.hpp"

namespace {

std::filesystem::path MakeTemporaryPath(std::string_view stem) {
    namespace fs = std::filesystem;
    const auto unique_suffix =
        static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count());
    return fs::temp_directory_path() /
           (std::string(stem) + "_" + std::to_string(unique_suffix) + ".pcap");
}

void RemoveIfExists(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
}

bool WriteBytesToFile(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        return false;
    }

    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(output);
}

int Fail(std::string_view message) {
    std::cerr << "[PcapReaderTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunPcapReaderTests() {
    namespace fs = std::filesystem;
    using namespace pcap_constrictor_afpacket;

    constexpr std::array<std::byte, 18> frame{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB},
        std::byte{0x08}, std::byte{0x00}, std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2E},
    };

    {
        const fs::path input_path = MakeTemporaryPath("pcap_reader_valid");
        {
            std::ofstream output(input_path, std::ios::binary);
            if (!output) {
                return Fail("unable to create valid reader input file");
            }

            const CapturedPacket packet{
                .packet = PacketView(std::span(frame), static_cast<std::uint32_t>(frame.size()), 64U),
                .timestamp = std::chrono::system_clock::time_point(std::chrono::seconds(1700000000) +
                                                                   std::chrono::microseconds(123456)),
                .ifindex = 0,
                .direction = PacketDirection::Unknown,
            };

            PcapWriter writer(output, 512U);
            writer.WritePacket(packet, static_cast<std::uint32_t>(frame.size()));
        }

        std::optional<PcapPacketRecord> record;
        {
            PcapReader reader;
            if (!reader.Open(input_path)) {
                RemoveIfExists(input_path);
                return Fail(reader.error_message());
            }

            record = reader.ReadNext();
            if (reader.global_header().link_type != kEthernetLinkType) {
                RemoveIfExists(input_path);
                return Fail("reader did not preserve Ethernet linktype");
            }
        }
        RemoveIfExists(input_path);
        if (!record) {
            return Fail("expected one packet from valid PCAP");
        }

        if (record->ts_sec != 1700000000U || record->ts_fraction != 123456U) {
            return Fail("reader timestamp fields mismatch");
        }
        if (record->captured_length != frame.size() || record->original_length != 64U) {
            return Fail("reader packet lengths mismatch");
        }
        for (std::size_t index = 0; index < frame.size(); ++index) {
            if (record->bytes[index] != frame[index]) {
                return Fail("reader packet bytes mismatch");
            }
        }
    }

    {
        const fs::path input_path = MakeTemporaryPath("pcap_reader_bad_magic");
        const std::vector<std::byte> bytes{
            std::byte{0x0A}, std::byte{0x0D}, std::byte{0x0D}, std::byte{0x0A},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        };

        if (!WriteBytesToFile(input_path, bytes)) {
            return Fail("unable to create unsupported-magic input file");
        }

        PcapReader reader;
        if (reader.Open(input_path)) {
            RemoveIfExists(input_path);
            return Fail("unsupported magic should fail");
        }
        RemoveIfExists(input_path);
        if (reader.error_message().find("pcapng") == std::string::npos &&
            reader.error_message().find("unsupported") == std::string::npos) {
            return Fail("unsupported magic error message should be useful");
        }
    }

    {
        const fs::path input_path = MakeTemporaryPath("pcap_reader_truncated_header");
        const std::vector<std::byte> bytes{
            std::byte{0xd4}, std::byte{0xc3}, std::byte{0xb2}, std::byte{0xa1},
            std::byte{0x02}, std::byte{0x00}, std::byte{0x04}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xff}, std::byte{0xff}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        };

        if (!WriteBytesToFile(input_path, bytes)) {
            return Fail("unable to create truncated-header input file");
        }

        bool observed_truncated_header = false;
        {
            PcapReader reader;
            if (!reader.Open(input_path)) {
                RemoveIfExists(input_path);
                return Fail("valid global header should open");
            }
            if (reader.ReadNext()) {
                RemoveIfExists(input_path);
                return Fail("truncated packet header should fail");
            }
            observed_truncated_header =
                reader.has_error() &&
                reader.incomplete_tail_info() &&
                reader.incomplete_tail_info()->kind == PcapIncompleteTailKind::PacketHeader;
        }
        RemoveIfExists(input_path);
        if (!observed_truncated_header) {
            return Fail("truncated packet header should record tail info");
        }
    }

    {
        const fs::path input_path = MakeTemporaryPath("pcap_reader_truncated_data");
        const std::vector<std::byte> bytes{
            std::byte{0xd4}, std::byte{0xc3}, std::byte{0xb2}, std::byte{0xa1},
            std::byte{0x02}, std::byte{0x00}, std::byte{0x04}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xff}, std::byte{0xff}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}, std::byte{0xdd}, std::byte{0xee},
        };

        if (!WriteBytesToFile(input_path, bytes)) {
            return Fail("unable to create truncated-data input file");
        }

        bool observed_truncated_data = false;
        {
            PcapReader reader;
            if (!reader.Open(input_path)) {
                RemoveIfExists(input_path);
                return Fail("valid global header should open for truncated data test");
            }
            if (reader.ReadNext()) {
                RemoveIfExists(input_path);
                return Fail("truncated packet data should fail");
            }
            observed_truncated_data =
                reader.has_error() &&
                reader.incomplete_tail_info() &&
                reader.incomplete_tail_info()->kind == PcapIncompleteTailKind::PacketData;
        }
        RemoveIfExists(input_path);
        if (!observed_truncated_data) {
            return Fail("truncated packet data should record tail info");
        }
    }

    return 0;
}
