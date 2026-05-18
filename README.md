# PcapConstrictorAFPacket

PcapConstrictorAFPacket is a Linux AF_PACKET live recorder with TLS/QUIC-aware adaptive PCAP capture. It is intended to reuse richer PcapConstrictor-style policy in userspace, without eBPF verifier constraints.

## Related projects

- `PcapConstrictor`: the main offline PCAP/PCAPNG constriction tool.
- `PcapConstrictorBPF`: an experimental Linux TC eBPF recorder.
- `PcapConstrictorAFPacket`: a userspace Linux live recorder built around AF_PACKET capture.

## Current status

The project is experimental but functional.

- Live capture has been smoke-tested on loopback and a real interface.
- Both `recvmsg` and `tpacket_v3` backends are available.
- Optional promiscuous mode, bounded capture, clean shutdown, and final stats are implemented.
- TLS `final_only` continuation behavior is aligned with the current upstream PcapConstrictor runtime behavior.
- TLS `stream` and `bulk` policies are recognized in config but are not supported yet.

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

## Testing

- Unit tests cover config parsing, PCAP I/O, decode, TLS, QUIC, and helper logic.
- Offline feed tests validate the deterministic offline pipeline.
- Golden PCAP compatibility tests compare constrained output byte-for-byte against inherited PcapConstrictor fixtures.
- Manual Linux smoke testing has been done on loopback and a real interface, with both `recvmsg` and `tpacket_v3`, plus basic promiscuous-mode and live TLS checks.

## License

Apache License 2.0. See [LICENSE]
