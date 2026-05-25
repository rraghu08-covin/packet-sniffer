#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include "capture.h"
#include "parser.h"
#include "dns.h"
#include "http_detect.h"
#include "stats.h"
#include "utils.h"

/* ── Filter configuration ────────────────────────────────────────── */

typedef struct {
    int  tcp_only, udp_only, icmp_only, dns_only, http_only, arp_only;
    char src_ip[46];
    char dst_ip[46];
    char host_ip[46];
    int  port;
    int  verbose;
    char output_file[256];
    int  stats_interval;
} Filters;

/* ── Globals for signal handler ──────────────────────────────────── */

static volatile sig_atomic_t g_running     = 1;
static Stats                 g_stats;
static int                   g_capture_fd  = -1;
static int                   g_was_promisc = 0;
static const char           *g_interface   = NULL;
static FILE                 *g_logfile     = NULL;

/* ── Signal handler ──────────────────────────────────────────────── */

static void sig_handler(int signo)
{
    (void)signo;
    g_running = 0;
    if (g_capture_fd >= 0) {
        close(g_capture_fd); /* unblock recvfrom */
        g_capture_fd = -1;
    }
}

/* ── Callback context passed through capture_loop ───────────────── */

typedef struct {
    Filters *filters;
    time_t   last_stats_time;
} CallbackCtx;

/* ── Apply all filters to a parsed packet ────────────────────────── */

static int packet_matches(const ParsedPacket *pp, const Filters *f)
{
    int any_proto = !(f->tcp_only | f->udp_only | f->icmp_only
                    | f->dns_only | f->http_only | f->arp_only);

    if (!any_proto) {
        if (f->arp_only  && pp->eth_type != ETHERTYPE_ARP) return 0;
        if (f->tcp_only  && !pp->tcp)                      return 0;
        if (f->udp_only  && !pp->udp)                      return 0;
        if (f->icmp_only && !pp->icmp)                     return 0;
        /* dns_only / http_only checked after protocol detection */
    }

    if (f->src_ip[0]  && strcmp(f->src_ip,  pp->src_ip) != 0) return 0;
    if (f->dst_ip[0]  && strcmp(f->dst_ip,  pp->dst_ip) != 0) return 0;
    if (f->host_ip[0] && strcmp(f->host_ip, pp->src_ip) != 0
                      && strcmp(f->host_ip, pp->dst_ip) != 0) return 0;

    if (f->port) {
        int found = 0;
        if (pp->tcp) {
            uint16_t sp = ntohs(pp->tcp->src_port);
            uint16_t dp = ntohs(pp->tcp->dst_port);
            if (sp == (uint16_t)f->port || dp == (uint16_t)f->port) found = 1;
        }
        if (pp->udp) {
            uint16_t sp = ntohs(pp->udp->src_port);
            uint16_t dp = ntohs(pp->udp->dst_port);
            if (sp == (uint16_t)f->port || dp == (uint16_t)f->port) found = 1;
        }
        if (!found) return 0;
    }

    return 1;
}

/* ── Print ARP payload ───────────────────────────────────────────── */

static void print_arp(const uint8_t *p, size_t len)
{
    if (len < 28) { printf("  <short ARP>\n"); return; }

    uint16_t oper;
    memcpy(&oper, p + 6, 2);
    oper = ntohs(oper);

    char sha[20], tha[20], spa[16], tpa[16];
    snprintf(sha, sizeof(sha), "%02x:%02x:%02x:%02x:%02x:%02x",
             p[8], p[9], p[10], p[11], p[12], p[13]);
    inet_ntop(AF_INET, p + 14, spa, sizeof(spa));
    snprintf(tha, sizeof(tha), "%02x:%02x:%02x:%02x:%02x:%02x",
             p[18], p[19], p[20], p[21], p[22], p[23]);
    inet_ntop(AF_INET, p + 24, tpa, sizeof(tpa));

    printf("  %s  %s (%s) \xe2\x86\x92 %s (%s)\n",
           oper == 1 ? "Request" : oper == 2 ? "Reply" : "Op?",
           spa, sha, tpa, tha);
}

/* ── Main packet handler callback ───────────────────────────────── */

static void handle_packet(const RawPacket *raw, void *userdata)
{
    if (!g_running) return;

    CallbackCtx *ctx = (CallbackCtx *)userdata;
    Filters     *f   = ctx->filters;

    ParsedPacket pp;
    if (parse_packet(raw->data, raw->len, &pp) < 0) return;

    /* ── Application-layer detection ───────────────────────── */
    DnsMessage dns;
    HttpInfo   http;
    int is_dns  = 0;
    int is_http = 0;

    if (pp.udp && pp.payload_len > 0) {
        uint16_t sp = ntohs(pp.udp->src_port);
        uint16_t dp = ntohs(pp.udp->dst_port);
        if (sp == 53 || dp == 53)
            is_dns = (dns_parse(pp.payload, pp.payload_len, &dns) == 0);
    }
    if (pp.tcp && pp.payload_len > 0) {
        uint16_t sp = ntohs(pp.tcp->src_port);
        uint16_t dp = ntohs(pp.tcp->dst_port);
        if ((sp == 53 || dp == 53) && pp.payload_len > 2)
            is_dns = (dns_parse(pp.payload + 2,
                                pp.payload_len - 2, &dns) == 0);
        if (sp == 80 || dp == 80 || sp == 8080 || dp == 8080)
            is_http = http_detect(pp.payload, pp.payload_len, &http);
    }

    /* ── Proto-only filters ──────────────────────────────────── */
    if (f->dns_only  && !is_dns)  return;
    if (f->http_only && !is_http) return;
    if (!packet_matches(&pp, f))  return;

    /* ── Determine label for stats and colour ───────────────── */
    const char *proto = "OTHER";
    if      (pp.eth_type == ETHERTYPE_ARP) proto = "ARP";
    else if (is_http)                       proto = "HTTP";
    else if (is_dns)                        proto = "DNS";
    else if (pp.tcp)                        proto = "TCP";
    else if (pp.udp)                        proto = "UDP";
    else if (pp.icmp)                       proto = "ICMP";
    else if (pp.ip6)                        proto = "IPv6";

    stats_update(&g_stats, pp.src_ip, proto, raw->len);

    /* ── Compact one-line output ─────────────────────────────── */
    char ts[32];
    format_timestamp(&raw->ts, ts, sizeof(ts));
    const char *col = proto_color(proto);

    printf("%s[%05d]%s  %s  %s%-6s%s",
           COL_GRAY, raw->pkt_num, COL_RESET, ts, col, proto, COL_RESET);

    if (pp.eth_type == ETHERTYPE_ARP) {
        print_arp(raw->data + sizeof(EthHeader),
                  raw->len  - sizeof(EthHeader));
    } else if (pp.src_ip[0]) {
        if (pp.tcp) {
            char flags[32];
            get_tcp_flags(pp.tcp->flags, flags, sizeof(flags));
            printf("  %s:%-6u  \xe2\x86\x92  %s:%-6u  %-14s  %zu bytes\n",
                   pp.src_ip, (unsigned)ntohs(pp.tcp->src_port),
                   pp.dst_ip, (unsigned)ntohs(pp.tcp->dst_port),
                   flags, raw->len);
        } else if (pp.udp) {
            printf("  %s:%-6u  \xe2\x86\x92  %s:%-6u  %zu bytes\n",
                   pp.src_ip, (unsigned)ntohs(pp.udp->src_port),
                   pp.dst_ip, (unsigned)ntohs(pp.udp->dst_port),
                   raw->len);
        } else if (pp.icmp) {
            printf("  %s  \xe2\x86\x92  %s  %s (type=%u code=%u)  %zu bytes\n",
                   pp.src_ip, pp.dst_ip,
                   icmp_type_str(pp.icmp->type),
                   pp.icmp->type, pp.icmp->code, raw->len);
        } else {
            printf("  %s  \xe2\x86\x92  %s  %zu bytes\n",
                   pp.src_ip, pp.dst_ip, raw->len);
        }
    } else {
        printf("  %zu bytes\n", raw->len);
    }

    /* DNS one-line summary (shown even without -v) */
    if (is_dns && dns.qdcount > 0) {
        printf("         %s%-9s%s  %-6s  %s\n",
               COL_MAGENTA,
               dns.is_response ? "DNS-RESP" : "DNS-QUERY", COL_RESET,
               dns_type_str(dns.questions[0].type),
               dns.questions[0].name);
    }

    /* HTTP one-line summary (shown even without -v) */
    if (is_http)
        http_print(&http);

    /* ── Verbose detail block ────────────────────────────────── */
    if (f->verbose) {
        if (pp.eth) {
            char ms[20], md[20];
            format_mac(pp.eth->src, ms, sizeof(ms));
            format_mac(pp.eth->dst, md, sizeof(md));
            printf("  Ethernet:  %s \xe2\x86\x92 %s\n", ms, md);
        }
        if (pp.ip4) {
            printf("  IPv4:      TTL=%-3u  TOS=0x%02x  ID=0x%04x  Len=%u\n",
                   pp.ip4->ttl, pp.ip4->tos,
                   ntohs(pp.ip4->id), ntohs(pp.ip4->total_len));
        }
        if (pp.ip6) {
            printf("  IPv6:      HopLim=%-3u  PayloadLen=%u\n",
                   pp.ip6->hop_limit, ntohs(pp.ip6->payload_len));
        }
        if (pp.tcp) {
            char flags[32];
            get_tcp_flags(pp.tcp->flags, flags, sizeof(flags));
            printf("  TCP:       Seq=%-10u  Ack=%-10u  Win=%-6u  %s\n",
                   ntohl(pp.tcp->seq), ntohl(pp.tcp->ack),
                   ntohs(pp.tcp->window), flags);
        }
        if (pp.udp)
            printf("  UDP:       Len=%u\n", ntohs(pp.udp->length));
        if (pp.icmp) {
            printf("  ICMP:      Type=%-3u (%s)  Code=%u  ID=%u  Seq=%u\n",
                   pp.icmp->type, icmp_type_str(pp.icmp->type),
                   pp.icmp->code,
                   ntohs(pp.icmp->id), ntohs(pp.icmp->seq));
        }
        if (is_dns)  dns_print(&dns);
        hex_dump(raw->data, raw->len);
        print_separator();
    }

    /* ── Log to file ─────────────────────────────────────────── */
    if (g_logfile) {
        fprintf(g_logfile, "[%05d] %s  %-6s  %-15s -> %-15s  %zu bytes\n",
                raw->pkt_num, ts, proto,
                pp.src_ip[0] ? pp.src_ip : "?",
                pp.dst_ip[0] ? pp.dst_ip : "?",
                raw->len);
        fflush(g_logfile);
    }

    /* ── Periodic stats ──────────────────────────────────────── */
    if (f->stats_interval > 0) {
        time_t now = time(NULL);
        if (now - ctx->last_stats_time >= (time_t)f->stats_interval) {
            ctx->last_stats_time = now;
            stats_print(&g_stats);
        }
    }
}

/* ── Usage / help text ───────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf(COL_BOLD "Usage: %s [OPTIONS]\n\n" COL_RESET, prog);
    printf("  -i, --interface IF      Capture interface (default: any)\n");
    printf("  -c, --count N           Stop after N packets\n");
    printf("  -p, --promisc           Enable promiscuous mode\n");
    printf("  -v, --verbose           Verbose output + hex dump\n");
    printf("  -o, --output FILE       Log packets to FILE\n");
    printf("  -h, --help              Show this help\n");
    printf("\nProtocol filters (show only matching packets):\n");
    printf("      --tcp               TCP only\n");
    printf("      --udp               UDP only\n");
    printf("      --icmp              ICMP only\n");
    printf("      --dns               DNS only\n");
    printf("      --http              HTTP only\n");
    printf("      --arp               ARP only\n");
    printf("\nAddress / port filters:\n");
    printf("      --src-ip IP         Match source IP\n");
    printf("      --dst-ip IP         Match destination IP\n");
    printf("      --host   IP         Match source or destination IP\n");
    printf("      --port   PORT       Match TCP/UDP port number\n");
    printf("\nStatistics:\n");
    printf("      --stats-interval N  Print stats every N seconds\n");
    printf("\nRequires root (CAP_NET_RAW).\n");
}

/* ── Startup banner ──────────────────────────────────────────────── */

static void print_banner(const char *iface, const Filters *f, int promisc)
{
    print_separator();
    printf(COL_BOLD COL_CYAN
           "  packet-sniffer  v1.0.0  \xe2\x80\x94  AF_PACKET/SOCK_RAW\n"
           COL_RESET);
    printf("  Interface     : %s\n", iface ? iface : "any");
    printf("  Promiscuous   : %s\n", promisc ? "yes" : "no");
    if (f->tcp_only)   printf("  Filter        : TCP only\n");
    if (f->udp_only)   printf("  Filter        : UDP only\n");
    if (f->icmp_only)  printf("  Filter        : ICMP only\n");
    if (f->dns_only)   printf("  Filter        : DNS only\n");
    if (f->http_only)  printf("  Filter        : HTTP only\n");
    if (f->arp_only)   printf("  Filter        : ARP only\n");
    if (f->host_ip[0]) printf("  Host filter   : %s\n", f->host_ip);
    if (f->src_ip[0])  printf("  Src IP filter : %s\n", f->src_ip);
    if (f->dst_ip[0])  printf("  Dst IP filter : %s\n", f->dst_ip);
    if (f->port)       printf("  Port filter   : %d\n",  f->port);
    printf("  Press Ctrl-C to stop and print statistics.\n");
    print_separator();
}

/* ── Entry point ─────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr,
                COL_RED "Error: packet-sniffer requires root privileges.\n"
                "  Run with:  sudo %s [OPTIONS]\n" COL_RESET, argv[0]);
        return EXIT_FAILURE;
    }

    CaptureConfig cfg = { NULL, 0, 0, 0 };
    Filters       f;
    memset(&f, 0, sizeof(f));

    /* ── Long-option table ───────────────────────────────────── */
    static const struct option long_opts[] = {
        { "interface",      required_argument, NULL, 'i' },
        { "count",          required_argument, NULL, 'c' },
        { "promisc",        no_argument,       NULL, 'p' },
        { "verbose",        no_argument,       NULL, 'v' },
        { "output",         required_argument, NULL, 'o' },
        { "help",           no_argument,       NULL, 'h' },
        { "tcp",            no_argument,       NULL,  1  },
        { "udp",            no_argument,       NULL,  2  },
        { "icmp",           no_argument,       NULL,  3  },
        { "dns",            no_argument,       NULL,  4  },
        { "http",           no_argument,       NULL,  5  },
        { "arp",            no_argument,       NULL,  6  },
        { "src-ip",         required_argument, NULL,  7  },
        { "dst-ip",         required_argument, NULL,  8  },
        { "host",           required_argument, NULL,  9  },
        { "port",           required_argument, NULL, 10  },
        { "stats-interval", required_argument, NULL, 11  },
        { NULL,             0,                 NULL,  0  },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:c:pvo:h",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': cfg.interface      = optarg;                    break;
        case 'c': cfg.count          = atoi(optarg);              break;
        case 'p': cfg.promiscuous    = 1;                         break;
        case 'v': f.verbose          = 1;                         break;
        case 'o': snprintf(f.output_file, sizeof(f.output_file),
                           "%s", optarg);                         break;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        case  1:  f.tcp_only   = 1;                               break;
        case  2:  f.udp_only   = 1;                               break;
        case  3:  f.icmp_only  = 1;                               break;
        case  4:  f.dns_only   = 1;                               break;
        case  5:  f.http_only  = 1;                               break;
        case  6:  f.arp_only   = 1;                               break;
        case  7:  snprintf(f.src_ip,  sizeof(f.src_ip),
                           "%s", optarg);                         break;
        case  8:  snprintf(f.dst_ip,  sizeof(f.dst_ip),
                           "%s", optarg);                         break;
        case  9:  snprintf(f.host_ip, sizeof(f.host_ip),
                           "%s", optarg);                         break;
        case 10:  f.port             = atoi(optarg);              break;
        case 11:  cfg.stats_interval = atoi(optarg);
                  f.stats_interval   = atoi(optarg);              break;
        default:  usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (f.output_file[0]) {
        g_logfile = fopen(f.output_file, "w");
        if (!g_logfile) { perror("fopen"); return EXIT_FAILURE; }
    }

    /* ── Install signal handlers ─────────────────────────────── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* ── Open raw socket ─────────────────────────────────────── */
    int fd = capture_open(cfg.interface, cfg.promiscuous);
    if (fd < 0) return EXIT_FAILURE;

    g_capture_fd  = fd;
    g_was_promisc = cfg.promiscuous;
    g_interface   = cfg.interface;

    stats_init(&g_stats);
    print_banner(cfg.interface, &f, cfg.promiscuous);

    /* ── Capture loop ────────────────────────────────────────── */
    CallbackCtx ctx;
    ctx.filters         = &f;
    ctx.last_stats_time = time(NULL);
    capture_loop(fd, handle_packet, &ctx, cfg.count);

    /* ── Teardown ────────────────────────────────────────────── */
    if (g_capture_fd >= 0) {
        capture_close(g_capture_fd, g_interface, g_was_promisc);
        g_capture_fd = -1;
    }
    stats_print(&g_stats);
    if (g_logfile) fclose(g_logfile);
    return EXIT_SUCCESS;
}
