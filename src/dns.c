#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"
#include "utils.h"

/* ── DNS header is always 12 bytes ─────────────────────────────── */
#define DNS_HDR_LEN 12

/* ── Big-endian multi-byte helpers ─────────────────────────────── */

static inline uint16_t ru16(const uint8_t *p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}

static inline uint32_t ru32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/* ── DNS name decompression (RFC 1035 §4.1.4) ──────────────────── */

/*
 * Decodes the DNS name at pkt[offset] into dst.
 * Follows compression pointers (0xC0 prefix) with a jump counter
 * to prevent infinite loops on malformed packets.
 *
 * Returns the number of bytes consumed from the original offset,
 * or -1 on error.
 */
static int dns_decode_name(const uint8_t *pkt, size_t pktlen,
                            size_t offset, char *dst, size_t dstsz)
{
    size_t out      = 0;
    int    consumed = -1; /* set once, on first entry into the name */
    size_t pos      = offset;
    int    jumps    = 0;

    dst[0] = '\0';

    while (pos < pktlen && jumps <= 20) {
        uint8_t lb = pkt[pos];

        /* ── End of name ────────────────────────────────────── */
        if (lb == 0) {
            if (consumed < 0)
                consumed = (int)(pos - offset + 1);
            if (out > 0 && dst[out - 1] == '.')
                dst[--out] = '\0'; /* strip trailing dot */
            else
                dst[out] = '\0';
            return consumed;
        }

        /* ── Compression pointer (top 2 bits == 11) ─────────── */
        if ((lb & 0xC0) == 0xC0) {
            if (pos + 1 >= pktlen) return -1;
            if (consumed < 0)
                consumed = (int)(pos - offset + 2);
            uint16_t ptr = (uint16_t)(((lb & 0x3F) << 8) | pkt[pos + 1]);
            if (ptr >= (uint16_t)pktlen) return -1;
            pos = ptr;
            jumps++;
            continue;
        }

        /* ── Regular label ───────────────────────────────────── */
        pos++;
        if (pos + lb > pktlen) return -1;
        for (uint8_t k = 0; k < lb; k++) {
            if (out + 1 < dstsz)
                dst[out++] = (char)pkt[pos + k];
        }
        if (out + 1 < dstsz)
            dst[out++] = '.';
        pos += lb;
    }

    return -1; /* ran off end without null terminator */
}

/* ── DNS record type → string ───────────────────────────────────── */

const char *dns_type_str(uint16_t type)
{
    switch (type) {
    case   1: return "A";
    case   2: return "NS";
    case   5: return "CNAME";
    case   6: return "SOA";
    case  12: return "PTR";
    case  15: return "MX";
    case  16: return "TXT";
    case  28: return "AAAA";
    case  33: return "SRV";
    case 255: return "ANY";
    default:  return "?";
    }
}

/* ── Parse a single resource record ─────────────────────────────── */

static int parse_rr(const uint8_t *pkt, size_t pktlen,
                    size_t offset, DnsRecord *rr)
{
    int nc = dns_decode_name(pkt, pktlen, offset, rr->name, sizeof(rr->name));
    if (nc < 0) return -1;
    offset += (size_t)nc;

    if (offset + 10 > pktlen) return -1;

    rr->type   = ru16(pkt + offset); offset += 2;
    rr->class_ = ru16(pkt + offset); offset += 2;
    rr->ttl    = ru32(pkt + offset); offset += 4;
    uint16_t rdlen = ru16(pkt + offset); offset += 2;

    if (offset + rdlen > pktlen) return -1;

    rr->rdata[0] = '\0';
    switch (rr->type) {
    case 1:  /* A    */
        if (rdlen == 4)
            inet_ntop(AF_INET,  pkt + offset, rr->rdata, sizeof(rr->rdata));
        break;
    case 28: /* AAAA */
        if (rdlen == 16)
            inet_ntop(AF_INET6, pkt + offset, rr->rdata, sizeof(rr->rdata));
        break;
    case  2: /* NS    */
    case  5: /* CNAME */
    case 12: /* PTR   */
        dns_decode_name(pkt, pktlen, offset, rr->rdata, sizeof(rr->rdata));
        break;
    case 15: /* MX */
        if (rdlen >= 3) {
            char mxname[DNS_MAX_NAME];
            dns_decode_name(pkt, pktlen, offset + 2, mxname, sizeof(mxname));
            snprintf(rr->rdata, sizeof(rr->rdata), "%u %s",
                     ru16(pkt + offset), mxname);
        }
        break;
    case 16: /* TXT */
        if (rdlen > 0) {
            uint8_t tlen  = pkt[offset];
            size_t  cplen = (tlen < sizeof(rr->rdata) - 1)
                            ? tlen : sizeof(rr->rdata) - 1;
            memcpy(rr->rdata, pkt + offset + 1, cplen);
            rr->rdata[cplen] = '\0';
        }
        break;
    default:
        snprintf(rr->rdata, sizeof(rr->rdata), "<rdlen=%u>", rdlen);
        break;
    }

    return nc + 10 + rdlen;
}

/* ── Main DNS parser ─────────────────────────────────────────────── */

int dns_parse(const uint8_t *data, size_t len, DnsMessage *out)
{
    if (len < DNS_HDR_LEN) return -1;
    memset(out, 0, sizeof(*out));

    out->id           = ru16(data);
    uint16_t flags    = ru16(data + 2);
    uint16_t qdcount  = ru16(data + 4);
    uint16_t ancount  = ru16(data + 6);

    out->is_response         = (flags >> 15) & 1;
    out->is_authoritative    = (flags >> 10) & 1;
    out->is_truncated        = (flags >>  9) & 1;
    out->recursion_desired   = (flags >>  8) & 1;
    out->recursion_available = (flags >>  7) & 1;
    out->rcode               = (uint8_t)(flags & 0x0F);

    size_t offset = DNS_HDR_LEN;

    /* ── Question section ────────────────────────────────────── */
    out->qdcount = 0;
    for (int i = 0; i < qdcount && i < DNS_MAX_RECORDS; i++) {
        DnsQuestion *q = &out->questions[out->qdcount];
        int nc = dns_decode_name(data, len, offset, q->name, sizeof(q->name));
        if (nc < 0) break;
        offset += (size_t)nc;
        if (offset + 4 > len) break;
        q->type   = ru16(data + offset); offset += 2;
        q->class_ = ru16(data + offset); offset += 2;
        out->qdcount++;
    }

    /* ── Answer section ──────────────────────────────────────── */
    out->ancount = 0;
    for (int i = 0; i < ancount && i < DNS_MAX_RECORDS; i++) {
        int consumed = parse_rr(data, len, offset,
                                &out->answers[out->ancount]);
        if (consumed < 0) break;
        offset += (size_t)consumed;
        out->ancount++;
    }

    return 0;
}

/* ── DNS pretty-printer ─────────────────────────────────────────── */

void dns_print(const DnsMessage *msg)
{
    printf(COL_MAGENTA "  DNS %s  ID=0x%04x  RCODE=%u" COL_RESET "\n",
           msg->is_response ? "RESPONSE" : "QUERY",
           msg->id, msg->rcode);

    for (int i = 0; i < msg->qdcount; i++) {
        printf("    ? %-8s  %s\n",
               dns_type_str(msg->questions[i].type),
               msg->questions[i].name);
    }
    for (int i = 0; i < msg->ancount; i++) {
        const DnsRecord *r = &msg->answers[i];
        printf("    \xe2\x9c\x93 %-8s  %-36s  TTL=%-6u  %s\n",
               dns_type_str(r->type), r->name, r->ttl, r->rdata);
    }
}
