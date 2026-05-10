# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux-oriented live recorder that is planned to reuse PcapConstrictor-style TLS/QUIC-aware adaptive capture logic for AF_PACKET capture.

Current status: offline classic PCAP feed mode is available, basic Linux AF_PACKET live capture is available, Ethernet/IP/TCP/UDP decode scaffolding is available, TLS Application Data constriction is available, and QUIC Long Header CID learning plus matched Short Header constriction is available.

## Current scope

- C++20 project skeleton with a small CMake setup
- INI-like config loader with defaults and validation
- Packet metadata/view types for future live capture integration
- Length clamping plus TLS Application Data prefix constriction for matching TCP packets
- Flow-aware QUIC Long Header CID learning and matched Short Header prefix constriction for matching UDP packets
- Little-endian classic PCAP writer (`DLT_EN10MB`, microsecond timestamps)
- Classic PCAP offline reader/feed path for reproducible policy validation
- Basic Linux AF_PACKET raw-socket live capture
- Ethernet/VLAN/IP/TCP/UDP decode scaffolding for policy classification
- Minimal standalone tests without an external framework

## Not in this milestone

- QUIC decryption, deep frame parsing, and connection migration
- `PACKET_MMAP` / `TPACKET_V3`
- libpcap, DPDK, pcapng, GUI, or multi-interface capture

## Example usage

```bash
./PcapConstrictorAFPacket --help
sudo ./PcapConstrictorAFPacket --config config.example.ini
./PcapConstrictorAFPacket --config config.example.ini --offline-input input.pcap
```

The binary can now run a deterministic offline pipeline:

`input.pcap -> PcapReader -> LiveCapturePolicy -> PcapWriter -> output.pcap`

For live AF_PACKET capture, `CAP_NET_RAW` or root privileges are required.

Current TLS configuration keys:

- `tls.enabled`
- `tls.ports`
- `tls.app_data_keep_record_bytes`
- `tls.app_data_continuation_keep_bytes`

Current continuation handling is limited. This milestone constricts TLS Application Data at record level within a single TCP segment and does not implement full stream reassembly.

Malformed or ambiguous TLS falls back conservatively to the existing default `snaplen` / `max_capture_len` behavior.

Current QUIC configuration keys:

- `quic.enabled`
- `quic.ports`
- `quic.short_header_keep_packet_bytes`
- `quic.require_dcid_match`
- `quic.allow_short_header_without_known_dcid`

Current QUIC handling is intentionally shallow. This milestone learns source CIDs from QUIC Long Header packets and constricts only matched Short Header packets using the learned destination CID for the opposite direction.

Unknown, malformed, unmapped, or mismatched QUIC short headers fall back conservatively to the existing default `snaplen` / `max_capture_len` behavior.

## Future milestones

1. Deeper TLS/QUIC policy coverage without changing capture plumbing
2. `PACKET_MMAP` / `TPACKET_V3`
