# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux-oriented live recorder that is planned to reuse PcapConstrictor-style TLS/QUIC-aware adaptive capture logic for AF_PACKET capture.

Current status: skeleton only. This milestone establishes the basic project structure, configuration loading, packet metadata types, simple length-based policy plumbing, classic PCAP writing, and offline smoke-path tests. AF_PACKET capture is not implemented yet.

## Current scope

- C++20 project skeleton with a small CMake setup
- INI-like config loader with defaults and validation
- Packet metadata/view types for future live capture integration
- Simple policy that only applies `default_snaplen` and `max_capture_len`
- Little-endian classic PCAP writer (`DLT_EN10MB`, microsecond timestamps)
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
```

The binary currently only validates configuration and reports that live AF_PACKET capture is not implemented yet.

## Future milestones

1. Offline packet feeder
2. Basic AF_PACKET `recvmsg` capture
3. Live policy integration
4. TLS constriction
5. QUIC constriction
6. `PACKET_MMAP` / `TPACKET_V3`
