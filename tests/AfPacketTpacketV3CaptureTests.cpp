#include <iostream>
#include <string>
#include <string_view>

#include "capture/AfPacketTpacketV3Capture.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[AfPacketTpacketV3CaptureTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunAfPacketTpacketV3CaptureTests() {
    using namespace pcap_constrictor_afpacket;

    {
        PolicyConfig::CaptureOptions options;
        std::string error;
        if (!AfPacketTpacketV3Capture::ValidateRingLayout(options, &error)) {
            return Fail("default ring layout should be valid");
        }
    }

    {
        PolicyConfig::CaptureOptions options;
        options.ring_block_size = 0U;
        std::string error;
        if (AfPacketTpacketV3Capture::ValidateRingLayout(options, &error)) {
            return Fail("zero ring_block_size should be invalid");
        }
    }

    {
        PolicyConfig::CaptureOptions options;
        options.ring_block_count = 0U;
        std::string error;
        if (AfPacketTpacketV3Capture::ValidateRingLayout(options, &error)) {
            return Fail("zero ring_block_count should be invalid");
        }
    }

    {
        PolicyConfig::CaptureOptions options;
        options.ring_frame_size = 0U;
        std::string error;
        if (AfPacketTpacketV3Capture::ValidateRingLayout(options, &error)) {
            return Fail("zero ring_frame_size should be invalid");
        }
    }

    {
        PolicyConfig::CaptureOptions options;
        options.ring_block_size = 4097U;
        options.ring_frame_size = 2048U;
        std::string error;
        if (AfPacketTpacketV3Capture::ValidateRingLayout(options, &error)) {
            return Fail("ring_block_size should be a multiple of ring_frame_size");
        }
    }

    if (AfPacketTpacketV3Capture::ConvertNanosecondsToMicroseconds(123456789U) != 123456U) {
        return Fail("nanosecond timestamp should truncate to microseconds");
    }
    if (AfPacketTpacketV3Capture::ConvertNanosecondsToMicroseconds(999999999U) != 999999U) {
        return Fail("nanosecond timestamp upper bound mismatch");
    }
    if (AfPacketTpacketV3Capture::ConvertNanosecondsToMicroseconds(1000000000U) != 999999U) {
        return Fail("nanosecond timestamp should clamp below one million microseconds");
    }

    return 0;
}
