#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "utils.h"

/* ── Hex dump ──────────────────────────────────────────────────── */

/*
 * Print data in xxd style:
 *   0000  61 62 63 64  65 66 67 68  ...  |abcdefgh...|
 * COL_GRAY is used for the offset and ASCII-border chars.
 */
void hex_dump(const uint8_t *data, size_t len)
{
    size_t i, j;
    for (i = 0; i < len; i += 16) {
        printf(COL_GRAY "  %04zx  " COL_RESET, i);

        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        printf(" " COL_GRAY "|" COL_RESET);
        for (j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? (char)c : '.');
        }
        printf(COL_GRAY "|" COL_RESET "\n");
    }
}

/* ── Timestamp formatter ───────────────────────────────────────── */

void format_timestamp(const struct timeval *tv, char *buf, size_t bufsz)
{
    struct tm *tm_info = localtime(&tv->tv_sec);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_info);
    snprintf(buf, bufsz, "%s.%06ld", tbuf, (long)tv->tv_usec);
}

/* ── MAC address formatter ─────────────────────────────────────── */

void format_mac(const uint8_t *mac, char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ── Protocol → ANSI colour ────────────────────────────────────── */

const char *proto_color(const char *proto)
{
    if (strcmp(proto, "TCP")    == 0) return COL_CYAN;
    if (strcmp(proto, "UDP")    == 0) return COL_GREEN;
    if (strcmp(proto, "ICMP")   == 0) return COL_YELLOW;
    if (strcmp(proto, "ICMPv6") == 0) return COL_YELLOW;
    if (strcmp(proto, "DNS")    == 0) return COL_MAGENTA;
    if (strcmp(proto, "HTTP")   == 0) return COL_BLUE;
    if (strcmp(proto, "ARP")    == 0) return COL_WHITE;
    return COL_GRAY;
}

/* ── Visual separator ──────────────────────────────────────────── */

void print_separator(void)
{
    printf(COL_GRAY
           "──────────────────────────────────────────────────────────────"
           COL_RESET "\n");
}
