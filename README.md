# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux-oriented live recorder that is planned to reuse PcapConstrictor-style TLS/QUIC-aware adaptive capture logic for AF_PACKET capture.

Current status: offline classic PCAP feed mode is available, and basic Linux AF_PACKET live capture is available. TLS/QUIC constriction is still future work.

## Current scope

- C++20 project skeleton with a small CMake setup
- INI-like config loader with defaults and validation
- Packet metadata/view types for future live capture integration
- Simple policy that only applies `default_snaplen` and `max_capture_len`
- Little-endian classic PCAP writer (`DLT_EN10MB`, microsecond timestamps)
- Classic PCAP offline reader/feed path for reproducible policy validation
- Basic Linux AF_PACKET raw-socket live capture
- Minimal standalone tests without an external framework

## Not in this milestone

- TLS parsing
- QUIC parsing
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

## Future milestones

1. TLS constriction
2. QUIC constriction
3. `PACKET_MMAP` / `TPACKET_V3`
