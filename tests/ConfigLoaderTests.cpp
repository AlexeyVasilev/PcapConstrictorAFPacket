#include <iostream>
#include <string_view>

#include "config/ConfigLoader.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[ConfigLoaderTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunConfigLoaderTests() {
    using namespace pcap_constrictor_afpacket;

    {
        const ConfigLoadResult defaults = ConfigLoader::LoadFromString("", "defaults.ini");
        if (!defaults) {
            return Fail("default config should load successfully");
        }
        if (defaults.config.capture.default_snaplen != 65535U) {
            return Fail("default_snaplen default mismatch");
        }
        if (defaults.config.capture.max_packets != 0U) {
            return Fail("capture.max_packets default mismatch");
        }
        if (defaults.config.capture.duration_sec != 0U) {
            return Fail("capture.duration_sec default mismatch");
        }
        if (defaults.config.general.min_saved_bytes_per_packet != 16U) {
            return Fail("general.min_saved_bytes_per_packet default mismatch");
        }
        if (defaults.config.capture.max_capture_len != 65535U) {
            return Fail("max_capture_len default mismatch");
        }
        if (!defaults.config.capture.interface.empty()) {
            return Fail("capture.interface default mismatch");
        }
        if (defaults.config.capture.output != "output.pcap") {
            return Fail("capture.output default mismatch");
        }
        if (!defaults.config.tls.enabled || defaults.config.tls.ports.size() != 2U) {
            return Fail("TLS defaults mismatch");
        }
        if (!defaults.config.quic.enabled || defaults.config.quic.ports.size() != 1U) {
            return Fail("QUIC defaults mismatch");
        }
        if (!defaults.config.stats.enabled) {
            return Fail("stats.enabled default mismatch");
        }
    }

    {
        constexpr std::string_view config_text = R"ini(
; comment
[capture]
interface = eth0
default_snaplen = 256
max_capture_len = 128
max_packets = 123456789
duration_sec = 90
output = constrained-output.pcap

[tls]
enabled = false
ports = 443, 993
app_data_keep_record_bytes = 32
app_data_continuation_keep_bytes = 16

[quic]
enabled = 1
ports = 443, 8443
short_header_keep_packet_bytes = 77
require_dcid_match = true
allow_short_header_without_known_dcid = 0

[stats]
enabled = false

[general]
min_saved_bytes_per_packet = 24
)ini";

        const ConfigLoadResult parsed = ConfigLoader::LoadFromString(config_text, "parsed.ini");
        if (!parsed) {
            return Fail(parsed.error);
        }

        if (parsed.config.capture.default_snaplen != 256U ||
            parsed.config.capture.max_capture_len != 128U) {
            return Fail("capture settings did not parse");
        }
        if (parsed.config.capture.max_packets != 123456789ULL ||
            parsed.config.capture.duration_sec != 90ULL) {
            return Fail("capture live limits did not parse");
        }
        if (parsed.config.general.min_saved_bytes_per_packet != 24U) {
            return Fail("general.min_saved_bytes_per_packet did not parse");
        }
        if (parsed.config.capture.interface != "eth0") {
            return Fail("capture.interface did not parse");
        }
        if (parsed.config.capture.output != "constrained-output.pcap") {
            return Fail("capture.output did not parse");
        }
        if (parsed.config.tls.enabled) {
            return Fail("tls.enabled did not parse");
        }
        if (parsed.config.tls.ports.size() != 2U ||
            parsed.config.tls.ports[0] != 443U ||
            parsed.config.tls.ports[1] != 993U) {
            return Fail("tls.ports did not parse");
        }
        if (parsed.config.quic.ports.size() != 2U ||
            parsed.config.quic.ports[1] != 8443U) {
            return Fail("quic.ports did not parse");
        }
        if (!parsed.config.quic.require_dcid_match ||
            parsed.config.quic.allow_short_header_without_known_dcid) {
            return Fail("quic booleans did not parse");
        }
        if (parsed.config.stats.enabled) {
            return Fail("stats.enabled did not parse");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[stats]\nenabled = maybe\n", "invalid.ini");
        if (invalid) {
            return Fail("invalid bool should fail");
        }
    }

    return 0;
}
