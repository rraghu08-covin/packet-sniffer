#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "capture.h"

/* ── Open raw AF_PACKET socket ─────────────────────────────────── */

int capture_open(const char *interface, int promiscuous)
{
    /* Receive all Ethernet frames on the wire */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        return -1;
    }

    /* Optionally bind to a specific interface */
    if (interface && strcmp(interface, "any") != 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl(SIOCGIFINDEX)");
            close(fd);
            return -1;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(fd);
            return -1;
        }

        /* Enable promiscuous mode via PACKET_ADD_MEMBERSHIP */
        if (promiscuous) {
            struct packet_mreq mr;
            memset(&mr, 0, sizeof(mr));
            mr.mr_ifindex = ifr.ifr_ifindex;
            mr.mr_type    = PACKET_MR_PROMISC;
            if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                           &mr, sizeof(mr)) < 0)
                perror("setsockopt(PACKET_ADD_MEMBERSHIP)"); /* non-fatal */
        }
    }

    return fd;
}

/* ── Promiscuous mode via ioctl ─────────────────────────────────── */

/*
 * Sets or clears IFF_PROMISC on the named interface.
 * Useful for toggling promisc independently of the socket.
 */
int set_promiscuous(int fd, const char *interface, int enable)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        return -1;
    }

    if (enable)
        ifr.ifr_flags |=  IFF_PROMISC;
    else
        ifr.ifr_flags &= ~IFF_PROMISC;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        return -1;
    }

    return 0;
}

/* ── Main capture loop ──────────────────────────────────────────── */

void capture_loop(int fd, PacketHandler handler, void *userdata, int count)
{
    static uint8_t buf[SNAP_LEN];
    static int     pkt_num = 0;

    struct sockaddr_ll saddr;
    socklen_t          saddr_len;

    while (count == 0 || pkt_num < count) {
        saddr_len = sizeof(saddr);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&saddr, &saddr_len);
        if (n < 0) {
            if (errno == EINTR)
                break;  /* interrupted by signal — exit cleanly */
            perror("recvfrom");
            break;
        }
        if (n == 0)
            continue;

        RawPacket pkt;
        pkt.data    = buf;
        pkt.len     = (size_t)n;
        pkt.pkt_num = ++pkt_num;
        gettimeofday(&pkt.ts, NULL);

        handler(&pkt, userdata);
    }
}

/* ── Socket teardown ───────────────────────────────────────────── */

void capture_close(int fd, const char *interface, int was_promisc)
{
    if (was_promisc && interface && strcmp(interface, "any") != 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
            struct packet_mreq mr;
            memset(&mr, 0, sizeof(mr));
            mr.mr_ifindex = ifr.ifr_ifindex;
            mr.mr_type    = PACKET_MR_PROMISC;
            setsockopt(fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
                       &mr, sizeof(mr));
        }
    }
    close(fd);
}
