#pragma once

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "capture/AfPacketCapture.hpp"
#include "capture/CapturedPacket.hpp"
#include "policy/PolicyConfig.hpp"

namespace pcap_constrictor_afpacket {

class AfPacketTpacketV3Capture {
public:
    AfPacketTpacketV3Capture() = default;
    ~AfPacketTpacketV3Capture();

    [[nodiscard]] static bool ValidateRingLayout(const PolicyConfig::CaptureOptions& config,
                                                 std::string* error_message = nullptr);
    [[nodiscard]] static std::uint32_t ConvertNanosecondsToMicroseconds(
        std::uint32_t nanoseconds) noexcept;

    [[nodiscard]] bool Open(const PolicyConfig::CaptureOptions& config);
    [[nodiscard]] AfPacketReceiveStatus ReceiveNext(
        CapturedPacket& packet,
        const volatile std::sig_atomic_t* stop_requested = nullptr);

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;
    [[nodiscard]] std::uint64_t non_fatal_receive_errors() const noexcept;
    [[nodiscard]] bool TryReadKernelStats(AfPacketKernelStats& stats) const noexcept;

private:
    void Close() noexcept;
    void SetError(std::string message);
    void DiscardCurrentBlock() noexcept;

#if defined(__linux__)
    [[nodiscard]] bool ValidateRingConfiguration(const PolicyConfig::CaptureOptions& config);
    [[nodiscard]] bool WaitForReadyBlock(const volatile std::sig_atomic_t* stop_requested,
                                         AfPacketReceiveStatus& status);
    [[nodiscard]] bool ActivateCurrentBlock();
    [[nodiscard]] const std::byte* current_block_base() const noexcept;
    void ReleaseCurrentBlock() noexcept;

    int socket_fd_{-1};
    std::byte* ring_mapping_{nullptr};
    std::size_t ring_mapping_size_{0};
    std::uint32_t block_size_{0};
    std::uint32_t block_count_{0};
    std::uint32_t poll_timeout_ms_{1000};
    std::uint32_t current_block_index_{0};
    std::uint32_t current_block_packet_index_{0};
    std::uint32_t current_block_packet_count_{0};
    std::uint32_t current_packet_offset_{0};
    bool current_block_active_{false};
    bool promiscuous_enabled_{false};
#endif

    std::string error_message_{};
    std::uint32_t interface_index_{0};
    std::uint64_t non_fatal_receive_errors_{0};
};

}  // namespace pcap_constrictor_afpacket
