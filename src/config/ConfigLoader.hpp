#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

struct ConfigLoadResult {
    PolicyConfig config{};
    std::string error{};

    [[nodiscard]] bool ok() const noexcept {
        return error.empty();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

class ConfigLoader {
public:
    static ConfigLoadResult LoadFromFile(const std::filesystem::path& path);
    static ConfigLoadResult LoadFromString(std::string_view text,
                                           std::string_view source_name = "<memory>");
};

}  // namespace pcap_constrictor_afpacket
