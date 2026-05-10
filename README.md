# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux-oriented live recorder that is planned to reuse PcapConstrictor-style TLS/QUIC-aware adaptive capture logic for AF_PACKET capture.

Current status: skeleton plus offline classic PCAP feed mode. This milestone establishes the basic project structure, configuration loading, packet metadata types, simple length-based policy plumbing, classic PCAP writing, and a deterministic offline packet-feed path for validating policy behavior before live capture. AF_PACKET capture is not implemented yet.

## Current scope

- C++20 project skeleton with a small CMake setup
- INI-like config loader with defaults and validation
- Packet metadata/view types for future live capture integration
- Simple policy that only applies `default_snaplen` and `max_capture_len`
- Little-endian classic PCAP writer (`DLT_EN10MB`, microsecond timestamps)
- Classic PCAP offline reader/feed path for reproducible policy validation
- Minimal standalone tests without an external framework

## Not in this milestone

- AF_PACKET capture
- TLS parsing
- QUIC parsing
- `PACKET_MMAP` / `TPACKET_V3`
- libpcap, DPDK, pcapng, GUI, or multi-interface capture

## Example usage

```bash
./PcapConstrictorAFPacket --help
./PcapConstrictorAFPacket --config config.example.ini
./PcapConstrictorAFPacket --config config.example.ini --offline-input input.pcap
```

The binary can now run a deterministic offline pipeline:

`input.pcap -> PcapReader -> LiveCapturePolicy -> PcapWriter -> output.pcap`

AF_PACKET live capture is still the next milestone.

## Future milestones

1. Basic AF_PACKET `recvmsg` capture
2. Live policy integration
3. TLS constriction
4. QUIC constriction
5. `PACKET_MMAP` / `TPACKET_V3`
