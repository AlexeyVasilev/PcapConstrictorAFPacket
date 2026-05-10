#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "policy/PolicyConfig.hpp"
#include "policy/TlsConstrictor.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[TlsConstrictorTests] " << message << '\n';
    return 1;
}

std::vector<std::byte> BuildIpv4TcpPacket(const std::vector<std::byte>& payload,
                                          const std::uint16_t src_port = 12345U,
                                          const std::uint16_t dst_port = 443U) {
    const std::size_t total_size = 14U + 20U + 20U + payload.size();
    const std::uint16_t ipv4_total_length = static_cast<std::uint16_t>(20U + 20U + payload.size());

    std::vector<std::byte> packet(total_size, std::byte{0});
    packet[12] = std::byte{0x08};
    packet[13] = std::byte{0x00};

    packet[14] = std::byte{0x45};
    packet[16] = static_cast<std::byte>((ipv4_total_length >> 8U) & 0xFFU);
    packet[17] = static_cast<std::byte>(ipv4_total_length & 0xFFU);
    packet[22] = std::byte{0x40};
    packet[23] = std::byte{0x06};
    packet[26] = std::byte{0x0a};
    packet[29] = std::byte{0x01};
    packet[30] = std::byte{0x0a};
    packet[33] = std::byte{0x02};

    packet[34] = static_cast<std::byte>((src_port >> 8U) & 0xFFU);
    packet[35] = static_cast<std::byte>(src_port & 0xFFU);
    packet[36] = static_cast<std::byte>((dst_port >> 8U) & 0xFFU);
    packet[37] = static_cast<std::byte>(dst_port & 0xFFU);
    packet[46] = std::byte{0x50};
    packet[47] = std::byte{0x18};

    std::copy(payload.begin(), payload.end(), packet.begin() + 54);
    return packet;
}

}  // namespace

int RunTlsConstrictorTests() {
    using namespace pcap_constrictor_afpacket;

    PolicyConfig::TlsOptions tls_config;
    tls_config.app_data_keep_record_bytes = 2U;

    {
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Handshake-only TLS packet should not be constricted");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}, std::byte{0xca}, std::byte{0xfe},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("ApplicationData TLS packet should be constricted");
        }
        if (result.output_len != 54U + 5U + 2U) {
            return Fail("ApplicationData constriction length mismatch");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}, std::byte{0xdd}, std::byte{0xee}, std::byte{0xff},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.output_len != 54U + 9U + 5U + 2U) {
            return Fail("Handshake plus ApplicationData constriction length mismatch");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x14}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x01},
            std::byte{0x15}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x02}, std::byte{0x03},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Multiple non-AppData records before AppData should still constrict");
        }
        if (result.output_len != 54U + 6U + 7U + 5U + 2U) {
            return Fail("Multi-record TLS constriction length mismatch");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::Malformed) {
            return Fail("Truncated TLS record header should fall back conservatively");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::Malformed) {
            return Fail("TLS record length beyond available payload should fall back");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0x47}, std::byte{0x45}, std::byte{0x54}, std::byte{0x20}, std::byte{0x2f}, std::byte{0x20},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result =
            TlsConstrictor::Evaluate(std::span(packet), 54U, payload.size(), tls_config);
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("Non-TLS TCP payload should not be treated as TLS");
        }
    }

    return 0;
}
