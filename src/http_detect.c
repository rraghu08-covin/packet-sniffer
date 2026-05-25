#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>   /* strncasecmp */
#include "http_detect.h"
#include "utils.h"

/* ── Known HTTP/1.x request methods ─────────────────────────────── */

static const char *const methods[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "CONNECT", "TRACE", NULL
};

/* ── Detect and parse HTTP/1.x ──────────────────────────────────── */

int http_detect(const uint8_t *payload, size_t len, HttpInfo *out)
{
    if (len < 8) return 0;

    memset(out, 0, sizeof(*out));
    out->content_length = -1;

    const char *buf = (const char *)payload;

    /* ── Request detection ──────────────────────────────────── */
    for (int i = 0; methods[i]; i++) {
        size_t mlen = strlen(methods[i]);
        if (len <= mlen + 1) continue;
        if (memcmp(buf, methods[i], mlen) != 0 || buf[mlen] != ' ') continue;

        out->is_request = 1;
        snprintf(out->method, sizeof(out->method), "%s", methods[i]);

        /* Parse URL (between method SP and next SP or CR) */
        const char *us = buf + mlen + 1;
        size_t      rl = len - (size_t)(us - buf);
        const char *ue = (const char *)memchr(us, ' ', rl);
        if (!ue) ue = (const char *)memchr(us, '\r', rl);
        if (ue) {
            size_t ul = (size_t)(ue - us);
            ul = ul < sizeof(out->url) - 1 ? ul : sizeof(out->url) - 1;
            memcpy(out->url, us, ul);
            out->url[ul] = '\0';
        }
        break;
    }

    /* ── Response detection ─────────────────────────────────── */
    if (!out->is_request && len >= 9 && memcmp(buf, "HTTP/", 5) == 0) {
        out->is_response = 1;
        const char *sp = (const char *)memchr(buf + 5, ' ', len - 5);
        if (sp && (size_t)(sp - buf) + 4 < len) {
            out->status_code = atoi(sp + 1);

            /* Parse status text after "NNN " */
            const char *tp = sp + 1;
            while (tp < buf + len && *tp != ' ') tp++;
            tp++;
            const char *te = (const char *)memchr(tp, '\r',
                              len - (size_t)(tp - buf));
            if (te) {
                size_t tl = (size_t)(te - tp);
                tl = tl < sizeof(out->status_text) - 1
                     ? tl : sizeof(out->status_text) - 1;
                memcpy(out->status_text, tp, tl);
                out->status_text[tl] = '\0';
            }
        }
    }

    if (!out->is_request && !out->is_response) return 0;

    /* ── Header field parsing ───────────────────────────────── */
    const char *p = (const char *)memchr(buf, '\n', len);
    if (!p) return 1;
    p++;

    while (p < buf + len) {
        const char *eol = (const char *)memchr(p, '\n',
                           len - (size_t)(p - buf));
        if (!eol) break;

        size_t llen = (size_t)(eol - p);
        if (llen == 0 || (llen == 1 && p[0] == '\r')) break; /* blank line */

        const char *col = (const char *)memchr(p, ':', llen);
        if (!col) { p = eol + 1; continue; }

        size_t      nlen = (size_t)(col - p);
        const char *val  = col + 1;
        while (val < eol && (*val == ' ' || *val == '\t')) val++;
        const char *ve   = eol;
        while (ve > val && (ve[-1] == '\r' || ve[-1] == '\n')) ve--;
        size_t      vlen = (size_t)(ve - val);

#define HMATCH(s) \
    (nlen == (sizeof(s) - 1) && strncasecmp(p, (s), nlen) == 0)
#define HCOPY(d) do { \
    size_t _n = vlen < sizeof(d) - 1 ? vlen : sizeof(d) - 1; \
    memcpy((d), val, _n); (d)[_n] = '\0'; } while (0)

        if      (HMATCH("Host"))           HCOPY(out->host);
        else if (HMATCH("User-Agent"))     HCOPY(out->user_agent);
        else if (HMATCH("Content-Type"))   HCOPY(out->content_type);
        else if (HMATCH("Content-Length")) {
            char tmp[32];
            size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
            memcpy(tmp, val, n); tmp[n] = '\0';
            out->content_length = atol(tmp);
        }

#undef HMATCH
#undef HCOPY

        p = eol + 1;
    }

    return 1;
}

/* ── HTTP pretty-printer ─────────────────────────────────────────── */

void http_print(const HttpInfo *info)
{
    if (info->is_request) {
        printf(COL_BLUE "  HTTP  %s %s" COL_RESET, info->method, info->url);
        if (info->host[0])
            printf("  [Host: %s]", info->host);
        printf("\n");
    } else {
        printf(COL_BLUE "  HTTP  %d %s" COL_RESET,
               info->status_code, info->status_text);
        if (info->content_type[0])
            printf("  [Content-Type: %s]", info->content_type);
        printf("\n");
    }
}
