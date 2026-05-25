/* capture.h — raw-socket capture interface */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

#define SNAP_LEN 65535

typedef struct {
    const char *interface;     /* NULL or "any" means all interfaces */
    int         promiscuous;
    int         count;         /* 0 = unlimited */
    int         stats_interval;/* 0 = disabled  */
} CaptureConfig;

typedef struct {
    uint8_t       *data;
    size_t         len;
    struct timeval ts;
    int            pkt_num;
} RawPacket;

typedef void (*PacketHandler)(const RawPacket *pkt, void *userdata);

int  capture_open(const char *interface, int promiscuous);
void capture_loop(int fd, PacketHandler handler, void *userdata, int count);
void capture_close(int fd, const char *interface, int was_promisc);
int  set_promiscuous(int fd, const char *interface, int enable);
