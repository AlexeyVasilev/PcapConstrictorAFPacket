#pragma once

#include <csignal>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "capture/CapturedPacket.hpp"

namespace pcap_constrictor_afpacket {

inline constexpr unsigned int kAfPacketTypeHost = 0U;
inline constexpr unsigned int kAfPacketTypeBroadcast = 1U;
inline constexpr unsigned int kAfPacketTypeMulticast = 2U;
inline constexpr unsigned int kAfPacketTypeOtherHost = 3U;
inline constexpr unsigned int kAfPacketTypeOutgoing = 4U;

enum class AfPacketReceiveStatus {
    Packet,
    Timeout,
    Interrupted,
    Error,
};

struct AfPacketKernelStats {
    std::uint64_t packets{0};
    std::uint64_t drops{0};
};

class AfPacketCapture {
public:
    explicit AfPacketCapture(std::uint32_t buffer_size = 65535U);
    ~AfPacketCapture();

    [[nodiscard]] bool Open(std::string_view interface_name);
    [[nodiscard]] AfPacketReceiveStatus ReceiveNext(
        CapturedPacket& packet,
        const volatile std::sig_atomic_t* stop_requested = nullptr);

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;
    [[nodiscard]] std::uint64_t non_fatal_receive_errors() const noexcept;
    [[nodiscard]] bool TryReadKernelStats(AfPacketKernelStats& stats) const noexcept;
    [[nodiscard]] static PacketDirection MapPacketTypeToDirection(unsigned int packet_type) noexcept;

private:
    void Close() noexcept;
    void SetError(std::string message);

#if defined(__linux__)
    int socket_fd_{-1};
#endif
    std::vector<std::byte> buffer_{};
    std::string error_message_{};
    std::uint32_t interface_index_{0};
    std::uint64_t non_fatal_receive_errors_{0};
};

}  // namespace pcap_constrictor_afpacket
