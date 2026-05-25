/* dns.h — DNS wire-format parser */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define DNS_MAX_NAME    256
#define DNS_MAX_RECORDS  16

typedef struct {
    char     name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t class_;
} DnsQuestion;

typedef struct {
    char     name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    char     rdata[DNS_MAX_NAME]; /* human-readable rdata */
} DnsRecord;

typedef struct {
    uint16_t    id;
    int         is_response;
    int         is_authoritative;
    int         is_truncated;
    int         recursion_desired;
    int         recursion_available;
    uint8_t     rcode;
    int         qdcount;
    int         ancount;
    DnsQuestion questions[DNS_MAX_RECORDS];
    DnsRecord   answers[DNS_MAX_RECORDS];
} DnsMessage;

int         dns_parse(const uint8_t *data, size_t len, DnsMessage *out);
void        dns_print(const DnsMessage *msg);
const char *dns_type_str(uint16_t type);
