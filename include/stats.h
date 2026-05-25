/* stats.h — per-protocol counters and top-talker tracking */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define MAX_TALKERS 256

typedef struct {
    char     ip[46];
    uint64_t packets;
    uint64_t bytes;
} Talker;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t dns_packets;
    uint64_t http_packets;
    uint64_t arp_packets;
    uint64_t ipv6_packets;
    uint64_t other_packets;
    time_t   start_time;
    Talker   talkers[MAX_TALKERS];
    int      talker_count;
} Stats;

void stats_init(Stats *s);
void stats_update(Stats *s, const char *src_ip,
                  const char *proto, size_t bytes);
void stats_print(const Stats *s);
