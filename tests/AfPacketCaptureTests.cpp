#include <iostream>
#include <string_view>

#include "capture/AfPacketCapture.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[AfPacketCaptureTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunAfPacketCaptureTests() {
    using namespace pcap_constrictor_afpacket;

    if (AfPacketCapture::MapPacketTypeToDirection(kAfPacketTypeHost) != PacketDirection::Incoming) {
        return Fail("PACKET_HOST mapping mismatch");
    }
    if (AfPacketCapture::MapPacketTypeToDirection(kAfPacketTypeOutgoing) != PacketDirection::Outgoing) {
        return Fail("PACKET_OUTGOING mapping mismatch");
    }
    if (AfPacketCapture::MapPacketTypeToDirection(kAfPacketTypeBroadcast) != PacketDirection::Broadcast) {
        return Fail("PACKET_BROADCAST mapping mismatch");
    }
    if (AfPacketCapture::MapPacketTypeToDirection(kAfPacketTypeMulticast) != PacketDirection::Multicast) {
        return Fail("PACKET_MULTICAST mapping mismatch");
    }
    if (AfPacketCapture::MapPacketTypeToDirection(kAfPacketTypeOtherHost) != PacketDirection::OtherHost) {
        return Fail("PACKET_OTHERHOST mapping mismatch");
    }
    if (AfPacketCapture::MapPacketTypeToDirection(999U) != PacketDirection::Unknown) {
        return Fail("unknown packet type should map to Unknown");
    }

    return 0;
}
