/* parser.h — wire-format struct definitions and parsed-packet context */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* ── Ethernet ──────────────────────────────────────────────────── */
#define ETH_ALEN 6

typedef struct __attribute__((packed)) {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
} EthHeader;

#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806

/* ── IPv4 ──────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  version_ihl;   /* version (4 bits) + IHL (4 bits) */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src[4];
    uint8_t  dst[4];
} IPv4Header;

/* ── IPv6 ──────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t version_tc_fl; /* version (4) + traffic class (8) + flow label (20) */
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} IPv6Header;

/* ── TCP ───────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset; /* high 4 bits = offset in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} TCPHeader;

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* ── UDP ───────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

/* ── ICMP ──────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;  /* valid for Echo Request/Reply (types 8/0) */
    uint16_t seq;
} ICMPHeader;

/* ── Parsed packet context ─────────────────────────────────────── */
typedef struct {
    EthHeader  *eth;
    int         eth_type;  /* ETHERTYPE_IP / IPV6 / ARP / other */

    IPv4Header *ip4;
    IPv6Header *ip6;

    TCPHeader  *tcp;
    UDPHeader  *udp;
    ICMPHeader *icmp;

    uint8_t    *payload;
    size_t      payload_len;

    char src_ip[46];  /* text-form IPv4 or IPv6 address */
    char dst_ip[46];
} ParsedPacket;

int         parse_packet(const uint8_t *data, size_t len, ParsedPacket *out);
void        get_tcp_flags(uint8_t flags, char *buf, size_t bufsz);
const char *icmp_type_str(uint8_t type);
