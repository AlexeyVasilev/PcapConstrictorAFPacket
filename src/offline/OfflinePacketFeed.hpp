#pragma once

#include <filesystem>
#include <string>

#include "policy/PolicyConfig.hpp"
#include "stats/CaptureStats.hpp"

namespace pcap_constrictor_afpacket {

struct OfflinePacketFeedResult {
    CaptureStats stats{};
    std::string error{};

    [[nodiscard]] bool ok() const noexcept {
        return error.empty();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

class OfflinePacketFeed {
public:
    static OfflinePacketFeedResult Run(const std::filesystem::path& input_path,
                                       const std::filesystem::path& output_path,
                                       const PolicyConfig& config);
};

}  // namespace pcap_constrictor_afpacket
