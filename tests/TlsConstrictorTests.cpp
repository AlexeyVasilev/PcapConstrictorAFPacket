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
                                          const std::uint32_t tcp_seq = 1U,
                                          const std::uint8_t tcp_flags = 0x18U) {
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
    packet[47] = static_cast<std::byte>(tcp_flags);

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
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("Unconfirmed ApplicationData-only TLS packet should be kept conservatively");
        }
        if (result.output_len != packet.size()) {
            return Fail("Unconfirmed ApplicationData-only TLS packet should keep the full packet");
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
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Handshake plus ApplicationData packet should be constricted");
        }
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
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("CCS/Alert before AppData without Handshake should keep conservatively");
        }
        if (result.output_len != packet.size()) {
            return Fail("Unconfirmed CCS/Alert/AppData packet should keep the full packet");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("Truncated unsynchronized TLS record header should keep conservatively as no record");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Confirmed partial TLS ApplicationData record should preserve a constrained prefix");
        }
        if (result.output_len != 54U + 9U + 2U) {
            return Fail("Confirmed partial TLS ApplicationData prefix length mismatch");
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
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x0a},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> middle_payload{
            std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}, std::byte{0x00},
        };

        const std::vector<std::byte> first_packet = BuildIpv4TcpPacket(first_payload, 12345U, 443U, 1U);
        const TlsConstrictResult first_result = evaluate(constrictor, first_packet);
        if (first_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Confirmed partial TLS ApplicationData packet should still be constricted");
        }
        if (first_result.output_len != 54U + 9U + 2U) {
            return Fail("Confirmed partial TLS ApplicationData prefix length mismatch");
        }

        const std::vector<std::byte> middle_packet =
            BuildIpv4TcpPacket(middle_payload, 12345U, 443U, 1U + static_cast<std::uint32_t>(first_payload.size()));

        const TlsConstrictResult middle_result = evaluate(constrictor, middle_packet);
        if (middle_result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Middle TLS ApplicationData continuation should be kept full under final_only");
        }
        if (middle_result.output_len != middle_packet.size()) {
            return Fail("Middle TLS ApplicationData continuation should keep the full packet");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> first_payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x0a},
            std::byte{0xde}, std::byte{0xad}, std::byte{0xbe},
        };
        const std::vector<std::byte> final_payload{
            std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}, std::byte{0x00}, std::byte{0x01}, std::byte{0x02},
        };

        const std::vector<std::byte> first_packet = BuildIpv4TcpPacket(first_payload, 12345U, 443U, 100U);
        const TlsConstrictResult first_result = evaluate(constrictor, first_packet);
        if (first_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("First confirmed partial TLS ApplicationData packet should be constricted");
        }

        const std::vector<std::byte> final_packet = BuildIpv4TcpPacket(
            final_payload,
            12345U,
            443U,
            100U + static_cast<std::uint32_t>(first_payload.size()));
        const TlsConstrictResult final_result = evaluate(constrictor, final_packet);
        if (final_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Exact final TLS ApplicationData continuation should be constricted");
        }
        if (final_result.output_len != 54U + 2U) {
            return Fail("Final TLS ApplicationData continuation keep length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> first_payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x0a},
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        };
        const std::vector<std::byte> boundary_payload{
            std::byte{0x55}, std::byte{0x55}, std::byte{0x55}, std::byte{0x55}, std::byte{0x55},
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x0c},
            std::byte{0x90}, std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94},
            std::byte{0x95}, std::byte{0x96}, std::byte{0x97},
        };
        const std::vector<std::byte> later_payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xa0}, std::byte{0xa1}, std::byte{0xa2}, std::byte{0xa3}, std::byte{0xa4}, std::byte{0xa5},
        };

        const std::vector<std::byte> first_packet = BuildIpv4TcpPacket(first_payload, 12345U, 443U, 2000U);
        const TlsConstrictResult first_result = evaluate(constrictor, first_packet);
        if (first_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Initial partial AppData start should be constricted");
        }

        const std::vector<std::byte> boundary_packet = BuildIpv4TcpPacket(
            boundary_payload,
            12345U,
            443U,
            2000U + static_cast<std::uint32_t>(first_payload.size()));
        const TlsConstrictResult boundary_result = evaluate(constrictor, boundary_packet);
        if (boundary_result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("final_only boundary packet should be kept conservatively");
        }
        if (boundary_result.output_len != boundary_packet.size()) {
            return Fail("final_only boundary packet should keep full length");
        }

        const std::vector<std::byte> later_packet = BuildIpv4TcpPacket(
            later_payload,
            12345U,
            443U,
            2000U + static_cast<std::uint32_t>(first_payload.size()) +
                static_cast<std::uint32_t>(boundary_payload.size()));
        const TlsConstrictResult later_result = evaluate(constrictor, later_packet);
        if (later_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("confirmed TLS stream should resynchronize on later AppData start");
        }
        if (later_result.output_len != 54U + 2U) {
            return Fail("resynchronized AppData start keep length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> handshake_payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06},
        };
        const std::vector<std::byte> appdata_payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xb0}, std::byte{0xb1}, std::byte{0xb2}, std::byte{0xb3}, std::byte{0xb4}, std::byte{0xb5},
        };

        const std::vector<std::byte> handshake_packet = BuildIpv4TcpPacket(handshake_payload, 12345U, 443U, 3000U);
        const TlsConstrictResult handshake_result = evaluate(constrictor, handshake_packet);
        if (handshake_result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Handshake packet should be kept");
        }

        const std::vector<std::byte> appdata_packet = BuildIpv4TcpPacket(appdata_payload, 12345U, 443U, 9999U);
        const TlsConstrictResult appdata_result = evaluate(constrictor, appdata_packet);
        if (appdata_result.disposition != TlsConstrictDisposition::AppDataPrefix) {
            return Fail("Confirmed TLS stream should resynchronize after TCP sequence mismatch");
        }
        if (appdata_result.output_len != 54U + 2U) {
            return Fail("TCP sequence mismatch resynchronization keep length mismatch");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> handshake_payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x06},
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06},
        };
        const std::vector<std::byte> syn_payload{};
        const std::vector<std::byte> appdata_payload{
            std::byte{0x17}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x08},
            std::byte{0xc0}, std::byte{0xc1}, std::byte{0xc2}, std::byte{0xc3}, std::byte{0xc4}, std::byte{0xc5},
        };

        const std::vector<std::byte> handshake_packet = BuildIpv4TcpPacket(handshake_payload, 12345U, 443U, 7000U);
        const TlsConstrictResult handshake_result = evaluate(constrictor, handshake_packet);
        if (handshake_result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Handshake packet should be kept before SYN reset");
        }

        const std::vector<std::byte> syn_packet = BuildIpv4TcpPacket(syn_payload, 12345U, 443U, 0U, 0x02U);
        const TlsConstrictResult syn_result = evaluate(constrictor, syn_packet);
        if (syn_result.disposition != TlsConstrictDisposition::NoApplicationData) {
            return Fail("Empty SYN packet should reset TLS state without triggering constriction");
        }

        const std::vector<std::byte> appdata_packet = BuildIpv4TcpPacket(
            appdata_payload,
            12345U,
            443U,
            7011U);
        const TlsConstrictResult appdata_result = evaluate(constrictor, appdata_packet);
        if (appdata_result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("SYN should clear TLS confirmation before later AppData-only packet");
        }
        if (appdata_result.output_len != appdata_packet.size()) {
            return Fail("Post-SYN AppData-only packet should keep the full packet");
        }
    }

    {
        TlsConstrictor constrictor;
        const std::vector<std::byte> payload{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00},
        };
        const std::vector<std::byte> packet = BuildIpv4TcpPacket(payload);

        const TlsConstrictResult result = evaluate(constrictor, packet);
        if (result.disposition != TlsConstrictDisposition::NoRecord) {
            return Fail("Truncated unsynchronized TLS-looking payload should keep conservatively as no record");
        }
    }

    return 0;
}
