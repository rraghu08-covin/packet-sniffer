# packet-sniffer — A Network Packet Sniffer in C

A production-quality, zero-dependency network packet sniffer written in **C11**.
Captures live traffic directly from the kernel using raw `AF_PACKET`/`SOCK_RAW` sockets
— no libpcap, no external libraries required.

## Features

| Feature | Details |
|---|---|
| **Raw capture** | `AF_PACKET`/`SOCK_RAW` — receives every Ethernet frame from the kernel |
| **Ethernet** | IEEE 802.3 frame parsing, MAC address display |
| **IPv4** | Version, IHL, TTL, TOS, ID, protocol, src/dst addresses |
| **IPv6** | Traffic class, flow label, hop limit, next header, src/dst addresses |
| **TCP** | Src/dst ports, sequence/ack numbers, window, flags (SYN/ACK/FIN/RST/PSH/URG) |
| **UDP** | Src/dst ports, length |
| **ICMP** | Type/code with human labels (Echo Request, TTL Exceeded, …) |
| **DNS** | Wire-format parsing with name compression; Q/A sections; A, AAAA, MX, CNAME, NS, PTR, TXT |
| **HTTP** | Request line (method + URL + Host), response status code; ports 80/8080 |
| **ARP** | Request/Reply with sender and target MAC + IP |
| **ANSI colour** | TCP=cyan, UDP=green, ICMP=yellow, DNS=magenta, HTTP=blue, ARP=white |
| **Hex dump** | `-v` — xxd-style dump with ASCII sidebar |
| **Protocol filter** | `--tcp` `--udp` `--icmp` `--dns` `--http` `--arp` |
| **IP filter** | `--src-ip` `--dst-ip` `--host` (either direction) |
| **Port filter** | `--port PORT` |
| **Count limit** | `-c N` — stop after N packets |
| **Interface** | `-i IF` — bind to specific interface or capture from all |
| **Promiscuous** | `-p` / `--promisc` |
| **Log to file** | `-o file.log` |
| **Statistics** | Protocol counts, total bytes, packet rate, top-5 talkers on exit |
| **Periodic stats** | `--stats-interval N` — print stats every N seconds |
| **Signal handling** | Ctrl-C prints stats and exits cleanly |

## Demo

```
──────────────────────────────────────────────────────────────
  packet-sniffer  v1.0.0  —  AF_PACKET/SOCK_RAW
  Interface     : eth0
  Promiscuous   : no
  Press Ctrl-C to stop and print statistics.
──────────────────────────────────────────────────────────────
[00001]  14:23:01.112233  TCP    192.168.1.5:52310  →  142.250.80.46:443    [SYN]           74 bytes
[00002]  14:23:01.113001  TCP    142.250.80.46:443  →  192.168.1.5:52310    [SYN ACK]       74 bytes
[00003]  14:23:01.115210  UDP    192.168.1.5:54321  →  8.8.8.8:53           42 bytes
         DNS-QUERY   A       www.example.com
[00004]  14:23:01.125432  UDP    8.8.8.8:53         →  192.168.1.5:54321    58 bytes
         DNS-RESP    A       www.example.com
[00005]  14:23:01.130011  TCP    192.168.1.5:52311  →  93.184.216.34:80     [PSH ACK]      421 bytes
  HTTP  GET /index.html  [Host: www.example.com]
[00006]  14:23:01.180997  ICMP   192.168.1.1  →  192.168.1.5  Echo Reply (type=0 code=0)  84 bytes
[00007]  14:23:01.181200  ARP    Request  192.168.1.1 (aa:bb:cc:dd:ee:ff) → 192.168.1.5 (00:00:00:00:00:00)
```

**Verbose mode (`-v`) adds per-packet detail:**

```
[00001]  14:23:01.112233  TCP    192.168.1.5:52310  →  142.250.80.46:443    [SYN]           74 bytes
  Ethernet:  aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
  IPv4:      TTL=64   TOS=0x00  ID=0x3a2f  Len=74
  TCP:       Seq=3735928559   Ack=0          Win=65535  [SYN]
  0000  45 00 00 4a 3a 2f 40 00  40 06 ...          |E..J:/..@......|
──────────────────────────────────────────────────────────────
```

## Project Structure

```
packet-sniffer/
├── include/
│   ├── capture.h       # Raw-socket capture API
│   ├── parser.h        # Ethernet/IP/TCP/UDP/ICMP struct definitions
│   ├── dns.h           # DNS wire-format parser
│   ├── http_detect.h   # HTTP/1.x request/response detector
│   ├── stats.h         # Per-protocol counters and top-talker tracking
│   └── utils.h         # ANSI colour macros, hex dump, formatters
├── src/
│   ├── main.c          # CLI arg parsing, signal handling, capture loop
│   ├── capture.c       # AF_PACKET/SOCK_RAW socket, promiscuous mode
│   ├── parser.c        # Ethernet → IPv4/IPv6 → TCP/UDP/ICMP parsing
│   ├── dns.c           # DNS name decompression, record parsing
│   ├── http_detect.c   # HTTP header field extraction
│   ├── stats.c         # Statistics aggregation and formatted output
│   └── utils.c         # hex_dump, format_timestamp, format_mac, colours
├── CMakeLists.txt
├── Makefile
└── README.md
```

## Requirements

- **Linux** — uses `AF_PACKET`/`SOCK_RAW`, Linux-specific kernel headers
- **Root** or `CAP_NET_RAW` capability
- **GCC ≥ 7** (or Clang ≥ 6) with C11 support
- **No external libraries** — zero dependencies beyond libc

## Build & Run

### Using Make

```bash
git clone https://github.com/rraghu08-covin/packet-sniffer.git
cd packet-sniffer
make
sudo ./packet-sniffer
```

### Using CMake

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
sudo ./packet-sniffer
```

### Debug build (AddressSanitizer + UBSan)

```bash
make debug
sudo ./packet-sniffer -c 100
```

### Install system-wide

```bash
sudo make install   # copies binary to /usr/local/bin/
```

## Usage

```
Usage: packet-sniffer [OPTIONS]

  -i, --interface IF      Capture interface (default: any)
  -c, --count N           Stop after N packets
  -p, --promisc           Enable promiscuous mode
  -v, --verbose           Verbose output + hex dump
  -o, --output FILE       Log packets to FILE
  -h, --help              Show this help

Protocol filters (show only matching packets):
      --tcp               TCP only
      --udp               UDP only
      --icmp              ICMP only
      --dns               DNS only
      --http              HTTP only
      --arp               ARP only

Address / port filters:
      --src-ip IP         Match source IP
      --dst-ip IP         Match destination IP
      --host   IP         Match source or destination IP
      --port   PORT       Match TCP/UDP port number

Statistics:
      --stats-interval N  Print stats every N seconds
```

### Examples

```bash
# Capture all traffic on eth0 in verbose mode
sudo ./packet-sniffer -i eth0 -v

# Watch DNS queries only
sudo ./packet-sniffer --dns

# Monitor HTTP traffic and log to file
sudo ./packet-sniffer --http -o capture.log

# Show only traffic to/from 8.8.8.8
sudo ./packet-sniffer --host 8.8.8.8

# Capture 500 TCP SYN packets on port 443 with stats every 10 s
sudo ./packet-sniffer --tcp --port 443 -c 500 --stats-interval 10

# Promiscuous mode on wlan0, stop after 1000 packets
sudo ./packet-sniffer -i wlan0 -p -c 1000

# Watch ICMP (ping) traffic between two hosts
sudo ./packet-sniffer --icmp --src-ip 192.168.1.5
```

## Architecture

| Module | Role |
|---|---|
| `capture.c` | Opens `AF_PACKET`/`SOCK_RAW` socket, optionally binds to an interface, enables promiscuous mode via `PACKET_ADD_MEMBERSHIP` and `SIOCSIFFLAGS`, runs the `recvfrom` loop |
| `parser.c` | Walks the packet buffer layer by layer: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP. Fills a `ParsedPacket` with typed pointers into the live buffer — zero-copy. |
| `dns.c` | Parses DNS wire format (RFC 1035) including name-compression pointer chains. Decodes question and answer sections for A, AAAA, MX, CNAME, NS, PTR, TXT records. |
| `http_detect.c` | Detects HTTP/1.x by checking for method keywords or `HTTP/` prefix. Parses the request line and key header fields (Host, Content-Type, Content-Length). |
| `stats.c` | Maintains per-protocol packet/byte counters and a fixed-size talker table. Prints a formatted report with `qsort`-ranked top-5 source IPs on exit. |
| `utils.c` | `hex_dump` (xxd-style), `format_timestamp` (HH:MM:SS.usec), `format_mac`, `proto_color` ANSI map, `print_separator`. |
| `main.c` | `getopt_long` CLI parsing, `sigaction` signal handling, filter evaluation, compact + verbose output formatting, optional file logging, periodic stats. |

## Concepts Demonstrated

- **Raw sockets** — `AF_PACKET`/`SOCK_RAW`, `ETH_P_ALL`, `recvfrom`
- **Ethernet / IP / TCP / UDP / ICMP headers** — manual struct-based wire parsing
- **Network byte order** — `ntohs`/`ntohl` throughout; explicit big-endian reads in DNS
- **DNS wire format** — RFC 1035 label encoding and pointer compression
- **Promiscuous mode** — `PACKET_ADD_MEMBERSHIP` and `SIOCSIFFLAGS`/`IFF_PROMISC`
- **Signal handling** — `sigaction`, `sig_atomic_t`, graceful shutdown pattern
- **POSIX system calls** — `socket`, `bind`, `ioctl`, `setsockopt`, `recvfrom`, `gettimeofday`
- **C11** — `_Generic`-compatible types, compound literals, designated initialisers
- **Zero-copy parsing** — typed pointers into the raw receive buffer, no malloc
- **`__attribute__((packed))`** — guaranteed struct layout for on-wire headers
- **Defensive parsing** — all length checks before pointer arithmetic; loop-guard in DNS decompression

## Author

**rraghu08-covin** — [github.com/rraghu08-covin](https://github.com/rraghu08-covin)

## License

MIT License — free to use, modify, and distribute.
