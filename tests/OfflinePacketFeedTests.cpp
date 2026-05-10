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

#include "capture/CapturedPacket.hpp"
#include "offline/OfflinePacketFeed.hpp"
#include "offline/PcapReader.hpp"
#include "policy/PolicyConfig.hpp"
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

int Fail(std::string_view message) {
    std::cerr << "[OfflinePacketFeedTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunOfflinePacketFeedTests() {
    namespace fs = std::filesystem;
    using namespace pcap_constrictor_afpacket;

    constexpr std::array<std::byte, 96> frame{};

    const fs::path input_path = MakeTemporaryPath("offline_feed_input");
    const fs::path output_path = MakeTemporaryPath("offline_feed_output");
    RemoveIfExists(input_path);
    RemoveIfExists(output_path);

    {
        std::ofstream output(input_path, std::ios::binary);
        if (!output) {
            return Fail("unable to create offline feed input");
        }

        const CapturedPacket packet{
            .packet = PacketView(std::span(frame), static_cast<std::uint32_t>(frame.size()), 120U),
            .timestamp = std::chrono::system_clock::time_point(std::chrono::seconds(1700000010) +
                                                               std::chrono::microseconds(42)),
            .ifindex = 0,
            .direction = PacketDirection::Unknown,
        };

        PcapWriter writer(output, 256U);
        writer.WritePacket(packet, static_cast<std::uint32_t>(frame.size()));
    }

    PolicyConfig config;
    config.capture.default_snaplen = 60U;
    config.capture.max_capture_len = 80U;
    config.capture.output = output_path;

    const OfflinePacketFeedResult result =
        OfflinePacketFeed::Run(input_path, config.capture.output, config);

    if (!result) {
        RemoveIfExists(input_path);
        RemoveIfExists(output_path);
        return Fail(result.error);
    }

    if (result.stats.packets_total != 1U ||
        result.stats.packets_written != 1U ||
        result.stats.bytes_input != frame.size() ||
        result.stats.bytes_output != 60U ||
        result.stats.bytes_saved != frame.size() - 60U) {
        RemoveIfExists(input_path);
        RemoveIfExists(output_path);
        return Fail("offline feed stats mismatch");
    }

    std::optional<PcapPacketRecord> record;
    {
        PcapReader reader;
        if (!reader.Open(output_path)) {
            RemoveIfExists(input_path);
            RemoveIfExists(output_path);
            return Fail(reader.error_message());
        }

        record = reader.ReadNext();
    }
    RemoveIfExists(input_path);
    RemoveIfExists(output_path);

    if (!record) {
        return Fail("offline feed should produce one output packet");
    }
    if (record->captured_length != 60U) {
        return Fail("offline feed should clamp output incl_len");
    }
    if (record->original_length != 120U) {
        return Fail("offline feed should preserve output orig_len");
    }
    for (std::size_t index = 0; index < record->bytes.size(); ++index) {
        if (record->bytes[index] != frame[index]) {
            return Fail("offline feed should preserve packet byte prefix");
        }
    }

    return 0;
}
