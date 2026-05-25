#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "stats.h"
#include "utils.h"

/* ── Initialise counters ─────────────────────────────────────────── */

void stats_init(Stats *s)
{
    memset(s, 0, sizeof(*s));
    s->start_time = time(NULL);
}

/* ── Update per-packet ───────────────────────────────────────────── */

void stats_update(Stats *s, const char *src_ip,
                  const char *proto, size_t bytes)
{
    s->total_packets++;
    s->total_bytes += (uint64_t)bytes;

    if      (strcmp(proto, "TCP")   == 0) s->tcp_packets++;
    else if (strcmp(proto, "UDP")   == 0) s->udp_packets++;
    else if (strcmp(proto, "ICMP")  == 0) s->icmp_packets++;
    else if (strcmp(proto, "DNS")   == 0) s->dns_packets++;
    else if (strcmp(proto, "HTTP")  == 0) s->http_packets++;
    else if (strcmp(proto, "ARP")   == 0) s->arp_packets++;
    else if (strcmp(proto, "IPv6")  == 0) s->ipv6_packets++;
    else                                   s->other_packets++;

    /* Update talker table */
    if (!src_ip || src_ip[0] == '\0') return;

    for (int i = 0; i < s->talker_count; i++) {
        if (strcmp(s->talkers[i].ip, src_ip) == 0) {
            s->talkers[i].packets++;
            s->talkers[i].bytes += (uint64_t)bytes;
            return;
        }
    }
    if (s->talker_count < MAX_TALKERS) {
        Talker *t = &s->talkers[s->talker_count++];
        strncpy(t->ip, src_ip, sizeof(t->ip) - 1);
        t->packets = 1;
        t->bytes   = (uint64_t)bytes;
    }
}

/* ── qsort comparator — descending packet count ─────────────────── */

static int talker_cmp(const void *a, const void *b)
{
    const Talker *ta = (const Talker *)a;
    const Talker *tb = (const Talker *)b;
    if (tb->packets > ta->packets) return  1;
    if (tb->packets < ta->packets) return -1;
    return 0;
}

/* ── Print formatted statistics ─────────────────────────────────── */

void stats_print(const Stats *s)
{
    time_t now      = time(NULL);
    double duration = difftime(now, s->start_time);
    if (duration < 1.0) duration = 1.0;
    double pps = (double)s->total_packets / duration;

    printf("\n");
    print_separator();
    printf(COL_BOLD "  Capture Statistics\n" COL_RESET);
    print_separator();
    printf("  Duration       : %.1f s\n",     duration);
    printf("  Total packets  : %llu\n",        (unsigned long long)s->total_packets);
    printf("  Total bytes    : %llu  (%.1f KB)\n",
           (unsigned long long)s->total_bytes,
           (double)s->total_bytes / 1024.0);
    printf("  Packet rate    : %.1f pps\n",   pps);

    printf("\n  " COL_BOLD "Protocol breakdown:\n" COL_RESET);

#define PROW(col, label, field) \
    printf("    " col "%-6s" COL_RESET "  %6llu  (%5.1f%%)\n", (label), \
           (unsigned long long)(s->field), \
           (s->total_packets) \
               ? (double)(s->field) / (double)(s->total_packets) * 100.0 \
               : 0.0)

    PROW(COL_CYAN,    "TCP",   tcp_packets);
    PROW(COL_GREEN,   "UDP",   udp_packets);
    PROW(COL_YELLOW,  "ICMP",  icmp_packets);
    PROW(COL_MAGENTA, "DNS",   dns_packets);
    PROW(COL_BLUE,    "HTTP",  http_packets);
    PROW(COL_WHITE,   "ARP",   arp_packets);
    PROW(COL_GRAY,    "IPv6",  ipv6_packets);
    PROW(COL_GRAY,    "Other", other_packets);
#undef PROW

    if (s->talker_count > 0) {
        Talker sorted[MAX_TALKERS];
        int    cnt = s->talker_count;
        memcpy(sorted, s->talkers, sizeof(Talker) * (size_t)cnt);
        qsort(sorted, (size_t)cnt, sizeof(Talker), talker_cmp);

        printf("\n  " COL_BOLD "Top talkers (src IP):\n" COL_RESET);
        int show = cnt < 5 ? cnt : 5;
        for (int i = 0; i < show; i++) {
            printf("    %2d. %-40s  %6llu pkts   %llu bytes\n",
                   i + 1, sorted[i].ip,
                   (unsigned long long)sorted[i].packets,
                   (unsigned long long)sorted[i].bytes);
        }
    }

    print_separator();
}
