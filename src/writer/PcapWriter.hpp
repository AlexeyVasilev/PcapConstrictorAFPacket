#pragma once

#include <cstdint>
#include <ostream>

#include "capture/CapturedPacket.hpp"

namespace pcap_constrictor_afpacket {

class PcapWriter {
public:
    static constexpr std::uint32_t kDefaultSnaplen = 65535;
    static constexpr std::uint32_t kEthernetLinkType = 1;  // DLT_EN10MB

    explicit PcapWriter(std::ostream& output,
                        std::uint32_t snaplen = kDefaultSnaplen) noexcept;

    void WriteGlobalHeader();
    void WritePacket(const CapturedPacket& packet);
    void WritePacket(const CapturedPacket& packet, std::uint32_t incl_len);

    [[nodiscard]] bool global_header_written() const noexcept {
        return global_header_written_;
    }

private:
    void WriteLe16(std::uint16_t value);
    void WriteLe32(std::uint32_t value);

    std::ostream& output_;
    std::uint32_t snaplen_{kDefaultSnaplen};
    bool global_header_written_{false};
};

}  // namespace pcap_constrictor_afpacket
