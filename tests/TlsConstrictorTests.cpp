#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "decode/PacketDecode.hpp"
#include "policy/PolicyConfig.hpp"
#include "policy/TlsConstrictor.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[TlsConstrictorTests] " << message << '\n';
    return 1;
}

std::vector<std::byte> BuildIpv4TcpPacket(const std::vector<std::byte>& payload,
                                          const std::uint16_t src_port = 12345U,
                                          const std::uint16_t dst_port = 443U,
                                          const std::uint32_t tcp_seq = 1U) {
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
    packet[38] = static_cast<std::byte>((tcp_seq >> 24U) & 0xFFU);
    packet[39] = static_cast<std::byte>((tcp_seq >> 16U) & 0xFFU);
    packet[40] = static_cast<std::byte>((tcp_seq >> 8U) & 0xFFU);
    packet[41] = static_cast<std::byte>(tcp_seq & 0xFFU);
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
    tls_config.app_data_continuation_keep_bytes = 2U;

    auto evaluate = [&](TlsConstrictor& constrictor, const std::vector<std::byte>& packet) {
        const PacketDecodeResult decoded = DecodePacket(std::span(packet));
        return constrictor.Evaluate(std::span(packet), decoded, tls_config);
    };

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Handshake-only TLS packet should not be constricted");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}, std::byte{0xca}, std::byte{0xfe},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("ApplicationData TLS packet should be constricted");
        }
        if (result.output_len != 54U + 2U) {
            return Fail("ApplicationData constriction length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}, std::byte{0xdd}, std::byte{0xee}, std::byte{0xff},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.output_len != 54U + 9U + 2U) {
            return Fail("Handshake plus ApplicationData constriction length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x14}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x01},
            std::byte{0x15}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x02}, std::byte{0x03},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Multiple non-AppData records before AppData should still constrict");
        }
        if (result.output_len != 54U + 6U + 7U + 2U) {
            return Fail("Multi-record TLS constriction length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::Malformed) {
            return Fail("Truncated TLS record header should fall back conservatively");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Truncated TLS ApplicationData record should still preserve a constrained prefix");
        }
        if (result.output_len != 54U + 2U) {
            return Fail("Truncated TLS ApplicationData prefix length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x47}, std::byte{0x45}, std::byte{0x54}, std::byte{0x20}, std::byte{0x2f}, std::byte{0x20},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("Non-TLS TCP payload should not be treated as TLS");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> first_payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x0a},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> second_payload{
            std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}, std::byte{0x00}, std::byte{0x01}, std::byte{0x02},
        };

        const std::vector<std::byte> first_packet = BuildIpv4TcpPacket(first_payload, 12345U, 443U, 1U);
        const TlsConstrictResult first_result = evaluate(constrictor, first_packet);
        if (first_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Partial TLS ApplicationData packet should still be constricted");
        }
        if (first_result.output_len != 54U + 2U) {
            return Fail("Partial TLS ApplicationData prefix length mismatch");
        }

        const std::vector<std::byte> second_packet = BuildIpv4TcpPacket(second_payload, 12345U, 443U, 9U);

        const TlsConstrictResult second_result = evaluate(constrictor, second_packet);
        if (second_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("TLS ApplicationData continuation packet should be constricted");
        }
        if (second_result.output_len != 54U + 2U) {
            return Fail("TLS continuation keep length mismatch");
        }
    }

    return 0;
}
