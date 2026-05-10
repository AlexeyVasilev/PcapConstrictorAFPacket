# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux-oriented live recorder that is planned to reuse PcapConstrictor-style TLS/QUIC-aware adaptive capture logic for AF_PACKET capture.

Current status: offline classic PCAP feed mode is available, basic Linux AF_PACKET live capture is available, Ethernet/IP/TCP/UDP decode scaffolding is available, TLS Application Data constriction is available, QUIC Long Header CID learning plus matched Short Header constriction is available, and golden offline PCAP compatibility tests are available.

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
- Golden offline compatibility tests that compare constrained PCAPs byte-for-byte with inherited PcapConstrictor fixtures

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
Basic live usage remains:

```bash
sudo ./PcapConstrictorAFPacket --config config.ini
```

Current live capture controls under `[capture]`:

- `capture.max_packets`
- `capture.duration_sec`

Both default to `0`, which means unlimited. These are intended as bounded smoke/demo controls for the current simple `recvfrom` live path and do not affect offline mode.

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

General configuration keys:

- `general.min_saved_bytes_per_packet`

This threshold applies only to protocol-aware extra constriction. Ordinary `default_snaplen` / `max_capture_len` clamping still behaves independently.

## Tests

- Unit tests cover config parsing, PCAP I/O, decode, TLS, QUIC, and offline/live-policy helper logic.
- Offline feed tests validate the deterministic `input.pcap -> policy -> output.pcap` path without live capture.
- Golden offline compatibility tests compare generated constrained PCAPs byte-for-byte against committed expected outputs inherited from PcapConstrictor.

Golden tests do not use live AF_PACKET capture, root privileges, or `CAP_NET_RAW`.

Live capture prints a final stats block on normal stop, bounded stop, or signal stop. This includes user-space counters such as packet and byte totals, plus `kernel_packets` and `kernel_drops` when Linux `PACKET_STATISTICS` is available at shutdown.

## Future milestones

1. Deeper TLS/QUIC policy coverage without changing capture plumbing
2. `PACKET_MMAP` / `TPACKET_V3`
