#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>
#include "parser.h"

/* ── Layer-4 dispatcher (shared for IPv4 and IPv6) ─────────────── */

static void parse_l4(uint8_t proto, const uint8_t *data,
                     size_t len, ParsedPacket *out)
{
    switch (proto) {

    case 6:  /* TCP */
        if (len < sizeof(TCPHeader)) break;
        out->tcp = (TCPHeader *)(void *)(uintptr_t)data;
        {
            uint8_t hdrlen =
                (uint8_t)(((out->tcp->data_offset >> 4) & 0x0F) * 4);
            if (hdrlen >= 20 && (size_t)hdrlen <= len) {
                out->payload     = (uint8_t *)(uintptr_t)(data + hdrlen);
                out->payload_len = len - hdrlen;
            }
        }
        break;

    case 17: /* UDP */
        if (len < sizeof(UDPHeader)) break;
        out->udp = (UDPHeader *)(void *)(uintptr_t)data;
        if (len > sizeof(UDPHeader)) {
            out->payload     = (uint8_t *)(uintptr_t)(data + sizeof(UDPHeader));
            out->payload_len = len - sizeof(UDPHeader);
        }
        break;

    case  1: /* ICMP   */
    case 58: /* ICMPv6 */
        if (len >= sizeof(ICMPHeader))
            out->icmp = (ICMPHeader *)(void *)(uintptr_t)data;
        break;

    default:
        break;
    }
}

/* ── Ethernet frame → fully-populated ParsedPacket ─────────────── */

int parse_packet(const uint8_t *data, size_t len, ParsedPacket *out)
{
    memset(out, 0, sizeof(*out));

    if (len < sizeof(EthHeader))
        return -1;

    out->eth      = (EthHeader *)(void *)(uintptr_t)data;
    out->eth_type = (int)ntohs(out->eth->ethertype);

    const uint8_t *ptr       = data + sizeof(EthHeader);
    size_t         remaining = len  - sizeof(EthHeader);

    /* ── IPv4 ──────────────────────────────────────────────────── */
    if (out->eth_type == ETHERTYPE_IP) {
        if (remaining < sizeof(IPv4Header))
            return 0;

        out->ip4      = (IPv4Header *)(void *)(uintptr_t)ptr;
        uint8_t ihl   = (uint8_t)((out->ip4->version_ihl & 0x0F) * 4);
        if (ihl < 20 || (size_t)ihl > remaining)
            return 0;

        inet_ntop(AF_INET, out->ip4->src, out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET, out->ip4->dst, out->dst_ip, sizeof(out->dst_ip));
        parse_l4(out->ip4->protocol, ptr + ihl, remaining - ihl, out);

    /* ── IPv6 ──────────────────────────────────────────────────── */
    } else if (out->eth_type == ETHERTYPE_IPV6) {
        if (remaining < sizeof(IPv6Header))
            return 0;

        out->ip6 = (IPv6Header *)(void *)(uintptr_t)ptr;
        inet_ntop(AF_INET6, out->ip6->src, out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET6, out->ip6->dst, out->dst_ip, sizeof(out->dst_ip));

        const uint8_t *l4     = ptr + sizeof(IPv6Header);
        size_t         l4_len = remaining - sizeof(IPv6Header);
        if (remaining >= sizeof(IPv6Header))
            parse_l4(out->ip6->next_header, l4, l4_len, out);
    }

    return 0;
}

/* ── TCP flags → "[SYN ACK]" string ────────────────────────────── */

void get_tcp_flags(uint8_t flags, char *buf, size_t bufsz)
{
    static const struct { uint8_t bit; const char *name; } map[] = {
        { TCP_SYN, "SYN" }, { TCP_ACK, "ACK" }, { TCP_FIN, "FIN" },
        { TCP_RST, "RST" }, { TCP_PSH, "PSH" }, { TCP_URG, "URG" },
    };
    size_t pos   = 0;
    int    first = 1;

    if (pos + 1 < bufsz) { buf[pos++] = '['; buf[pos] = '\0'; }

    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (!(flags & map[i].bit)) continue;
        if (!first && pos + 1 < bufsz) { buf[pos++] = ' '; buf[pos] = '\0'; }
        size_t nlen = strlen(map[i].name);
        if (pos + nlen < bufsz) {
            memcpy(buf + pos, map[i].name, nlen);
            pos += nlen;
            buf[pos] = '\0';
        }
        first = 0;
    }
    if (flags == 0 && pos + 4 < bufsz) {
        memcpy(buf + pos, "---", 3);
        pos += 3;
        buf[pos] = '\0';
    }
    if (pos + 1 < bufsz) { buf[pos++] = ']'; buf[pos] = '\0'; }
}

/* ── ICMP type → human-readable string ─────────────────────────── */

const char *icmp_type_str(uint8_t type)
{
    switch (type) {
    case  0: return "Echo Reply";
    case  3: return "Dest Unreachable";
    case  4: return "Source Quench";
    case  5: return "Redirect";
    case  8: return "Echo Request";
    case  9: return "Router Advertisement";
    case 10: return "Router Solicitation";
    case 11: return "TTL Exceeded";
    case 12: return "Parameter Problem";
    case 13: return "Timestamp";
    case 14: return "Timestamp Reply";
    case 17: return "Address Mask Request";
    case 18: return "Address Mask Reply";
    default: return "Unknown";
    }
}
