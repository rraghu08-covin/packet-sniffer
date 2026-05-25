/* http_detect.h — HTTP/1.x request/response detector */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    int  is_request;
    int  is_response;
    char method[16];
    char url[256];
    char host[128];
    char user_agent[128];
    int  status_code;
    char status_text[64];
    char content_type[64];
    long content_length;  /* -1 if absent */
} HttpInfo;

int  http_detect(const uint8_t *payload, size_t len, HttpInfo *out);
void http_print(const HttpInfo *info);
