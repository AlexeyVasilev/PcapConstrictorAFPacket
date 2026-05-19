# PcapConstrictorAFPacket

PcapConstrictorAFPacket is the practical Linux userspace live recorder in the PcapConstrictor project family. It captures packets from live Linux interfaces with AF_PACKET and applies PcapConstrictor-style TLS/QUIC-aware adaptive PCAP capture in userspace.

Compared with the main offline tool, it has a smaller policy surface today, but it is intended to be the practical Linux live-capture path without eBPF verifier constraints.

## Project family

| Project | Role | Use when |
|---|---|---|
| [PcapConstrictor](https://github.com/AlexeyVasilev/PcapConstrictor) | Main offline PCAP/PCAPNG constriction tool | You already have capture files and want the richest policy support, including TLS `final_only`/`stream`/`bulk`, QUIC, PCAPNG, reinflate/restore, checksum policies, stats, and decision logs. |
| [PcapConstrictorAFPacket](https://github.com/AlexeyVasilev/PcapConstrictorAFPacket) | Linux AF_PACKET live recorder | You want practical Linux live capture with userspace PcapConstrictor-style policy. Supports TLS `final_only` and QUIC CID-aware short-header constriction, but not TLS `stream`/`bulk`. |
| [PcapConstrictorWinPacket](https://github.com/AlexeyVasilev/PcapConstrictorWinPacket) | Windows Npcap/libpcap live recorder | You want practical Windows live capture with Npcap and a policy scope similar to AFPacket. Supports TLS `final_only` and QUIC known-DCID constriction, but not TLS `stream`/`bulk`. |
| [PcapConstrictorBPF](https://github.com/AlexeyVasilev/PcapConstrictorBPF) | Experimental Linux TC eBPF recorder | You want a research eBPF project demonstrating TC hooks, BPF maps, verifier-friendly parsing, and a much smaller live-capture policy subset. |

## Current status

The project is experimental but functional.

- Live capture has been smoke-tested on loopback and a real interface.
- Both `recvmsg` and `tpacket_v3` / `PACKET_MMAP` backends are available.
- Optional promiscuous mode, bounded capture, clean shutdown, and final stats are implemented.
- TLS `final_only` continuation behavior is aligned with the current upstream PcapConstrictor runtime behavior.
- TLS `stream` and `bulk` policies are recognized in config but are not supported yet.
- QUIC matched short-header constriction is intended to stay close to PcapConstrictor behavior for learned-CID flows.
- For practical Linux live capture, this project is the main userspace recorder; the BPF project is narrower and more experimental.

## Features

- Linux AF_PACKET live capture
- `recvmsg` backend
- `TPACKET_V3` / `PACKET_MMAP` backend
- Optional promiscuous mode
- Classic PCAP output (`DLT_EN10MB`, microsecond timestamps)
- INI-style config file
- Bounded live capture with `max_packets` and `duration_sec`
- Final stats on normal stop, bounded stop, or signal stop
- Offline classic-PCAP feed mode
- Golden offline compatibility tests using inherited PcapConstrictor fixtures
- Ethernet/VLAN/IPv4/IPv6/TCP/UDP decode
- TLS Application Data constriction with upstream-compatible `final_only` continuation handling
- QUIC Long Header CID learning and matched Short Header constriction

This repository writes classic PCAP, supports offline compatibility mode for deterministic regression testing, and intentionally does not claim the full offline policy scope of `PcapConstrictor`.

## Basic usage

Live capture:

```bash
sudo ./PcapConstrictorAFPacket --config config.ini
```

Offline feed mode:

```bash
./PcapConstrictorAFPacket --config config.ini --offline-input input.pcap
```

The offline path is deterministic:

`input.pcap -> PcapReader -> LiveCapturePolicy -> PcapWriter -> output.pcap`

## Example config

```ini
[general]
min_saved_bytes_per_packet = 16

[capture]
backend = recvmsg
# backend = tpacket_v3
interface = eth0
output = output.pcap
promiscuous = false
default_snaplen = 65535
max_capture_len = 65535
max_packets = 0
duration_sec = 0
ring_block_size = 1048576
ring_block_count = 64
ring_frame_size = 2048
block_timeout_ms = 64

[tls]
enabled = true
ports = 443, 8443
app_data_keep_record_bytes = 256
app_data_continuation_keep_bytes = 64
app_data_continuation_policy = final_only

[quic]
enabled = true
ports = 443
short_header_keep_packet_bytes = 128
require_dcid_match = false
allow_short_header_without_known_dcid = true

[stats]
enabled = true
```

## Backend notes

- `recvmsg` is the simpler backend and the default.
- `tpacket_v3` uses a Linux `PACKET_MMAP` RX ring and is intended for lower-overhead capture.
- `tpacket_v3` is still experimental.
- Ring settings should usually be left at their defaults unless you are tuning for a specific environment.

## Permissions

Using `sudo` is the simplest way to run live capture:

```bash
sudo ./PcapConstrictorAFPacket --config config.ini
```

`CAP_NET_RAW` can also be granted to the binary:

```bash
sudo setcap cap_net_raw+ep ./PcapConstrictorAFPacket
```

Both live backends use the same AF_PACKET permissions. Promiscuous mode does not require a different execution model, but it may not be meaningful on loopback or some virtual interfaces.

## TLS and QUIC policy notes

TLS:

- `tls.app_data_continuation_policy = final_only` is supported.
- `stream` and `bulk` are recognized but intentionally unsupported for now.
- Malformed or ambiguous TLS falls back conservatively to normal `default_snaplen` / `max_capture_len` behavior.
- No TLS decryption is performed.

QUIC:

- Current handling is invariant-header/CID based.
- The policy learns source CIDs from Long Header packets and constricts only matched Short Header packets.
- For matched short-header packets, the goal is to stay close to PcapConstrictor behavior while remaining practical for live userspace capture.
- Unknown, malformed, unmapped, or mismatched packets fall back conservatively.
- No QUIC decryption or connection migration support is implemented.

## Stats

The final stats block may include:

- `packets_total`: packets accepted into the policy pipeline.
- `packets_written`: packets emitted to the output PCAP.
- `bytes_input`: total original input bytes observed by the pipeline.
- `bytes_output`: total saved bytes written to the output PCAP.
- `bytes_saved`: `bytes_input - bytes_output`.
- `receive_errors`: internal receive/setup or malformed-capture-structure errors.
- `kernel_packets`: kernel-side packet count from `PACKET_STATISTICS` when available.
- `kernel_drops`: kernel-side drop count from `PACKET_STATISTICS` when available.
- `tls_appdata_constricted`: TLS packets shortened by policy.
- `tls_fallback`: TLS candidates that fell back conservatively.
- `quic_long_header`: QUIC Long Header packets observed.
- `quic_short_matched`: QUIC Short Header packets matched against learned CID state.
- `quic_short_constricted`: QUIC Short Header packets actually shortened.
- `quic_fallback`: QUIC candidates that fell back conservatively.

## Known limitations

- Linux only
- Classic PCAP output only
- No pcapng output
- No full TCP stream reassembly
- TLS supports conservative `final_only` continuation behavior only
- TLS `stream` and `bulk` policies are not supported yet
- No TLS decryption
- QUIC handling is invariant-header/CID based, without decryption
- No QUIC connection migration support
- `TPACKET_V3` backend is experimental
- Not a replacement for `tcpdump` or Wireshark
- Malformed or ambiguous packets fall back conservatively
- Fewer policy modes than the main `PcapConstrictor` offline tool

## Testing

- Unit tests cover config parsing, PCAP I/O, decode, TLS, QUIC, and helper logic.
- Offline feed tests validate the deterministic offline pipeline.
- Golden PCAP compatibility tests compare constrained output byte-for-byte against inherited PcapConstrictor fixtures.
- Manual Linux smoke testing has been done on loopback and a real interface, with both `recvmsg` and `tpacket_v3`, plus basic promiscuous-mode and live TLS checks.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Alexey Vasilev.

