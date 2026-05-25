/* utils.h — ANSI colour macros and common utility prototypes */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

/* ── ANSI colour codes ─────────────────────────────────────────── */
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_RED     "\033[31m"
#define COL_GREEN   "\033[32m"
#define COL_YELLOW  "\033[33m"
#define COL_BLUE    "\033[34m"
#define COL_MAGENTA "\033[35m"
#define COL_CYAN    "\033[36m"
#define COL_WHITE   "\033[37m"
#define COL_GRAY    "\033[90m"

void        hex_dump(const uint8_t *data, size_t len);
void        format_timestamp(const struct timeval *tv, char *buf, size_t bufsz);
void        format_mac(const uint8_t *mac, char *buf, size_t bufsz);
const char *proto_color(const char *proto);
void        print_separator(void);
