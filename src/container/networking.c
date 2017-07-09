#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>
#include <pty.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "container/networking.h"
#include "container/network_relay.h"
#include "container/signaling.h"

int open_tap() {
    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

    if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);

        return err;
    }

    return fd;
}

void container_initialize_network_namespace(container_t *container) {
    sethostname(container->hostname, strlen(container->hostname));

    int tap_fd;
    if((tap_fd = open_tap()) < 0) {
        fprintf(stderr, "[!] Failed to create eth0\n");
        exit(EXIT_FAILURE);
    }

    system("ip link set dev lo up");
    system("ip link set dev eth0 up");
    system("ip addr add 10.0.15.2 dev eth0");
    system("ip route add 10.0.15.0/24 dev eth0");
    system("ip route add default via 10.0.15.1");

    if(send_fd(container->child_signaling_fd, tap_fd) < 0) {
        fprintf(stderr, "[!] Failed to send eth0 outside of the container\n");
        exit(EXIT_FAILURE);
    }

    if(close(tap_fd) < 0) {
        fprintf(stderr, "[!] Failed to abandon eth0\n");
        exit(EXIT_FAILURE);
    }
}

void container_spawn_network_relay(container_t *container) {
    int tap_fd;
    if((tap_fd = recv_fd(container->parent_signaling_fd)) < 0) {
        fprintf(stderr, "[!] Cannot claim eth0.\n");
        exit(EXIT_FAILURE);
    }

    ip_addr_t ip;
    ip_addr_t netmask;

    IP4_ADDR(&ip, 10,0,15,1);
    IP4_ADDR(&netmask, 255,255,255,0);

    if(spawn_network_relay(tap_fd, &ip, &netmask) == NULL) {
        fprintf(stderr, "[!] Failed to spawn network relay.\n");
        exit(EXIT_FAILURE);
    }
}
