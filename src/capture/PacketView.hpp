#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace pcap_constrictor_afpacket {

class PacketView {
public:
    PacketView() = default;

    PacketView(std::span<const std::byte> data,
               std::uint32_t captured_len,
               std::uint32_t original_len) noexcept
        : data_(data),
          captured_len_(captured_len),
          original_len_(original_len) {}

    [[nodiscard]] std::span<const std::byte> data() const noexcept {
        return data_;
    }

    [[nodiscard]] std::size_t data_size() const noexcept {
        return data_.size();
    }

    [[nodiscard]] std::uint32_t captured_len() const noexcept {
        return captured_len_;
    }

    [[nodiscard]] std::uint32_t original_len() const noexcept {
        return original_len_;
    }

    [[nodiscard]] bool IsLengthSane() const noexcept {
        return captured_len_ <= data_.size() && captured_len_ <= original_len_;
    }

    [[nodiscard]] std::uint32_t safe_captured_len() const noexcept {
        return static_cast<std::uint32_t>(std::min<std::size_t>(captured_len_, data_.size()));
    }

private:
    std::span<const std::byte> data_{};
    std::uint32_t captured_len_{0};
    std::uint32_t original_len_{0};
};

}  // namespace pcap_constrictor_afpacket
