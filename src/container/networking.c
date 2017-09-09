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
#include "network_relay/network_relay.h"
#include "container/signaling.h"

static int open_tap() {
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

container_error_t container_networking_initialize_child(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->hostname == NULL) {
        return CONTAINER_ERROR_ARG;
    }

    if(sethostname(container->hostname, strlen(container->hostname)) < 0) {
        return CONTAINER_ERROR_NET_HOSTNAME;
    }

    if(!container->networking_enabled) {
        return CONTAINER_ERROR_OKAY;
    }

    int tap_fd;
    if((tap_fd = open_tap()) < 0) {
        return CONTAINER_ERROR_NET_TAP;
    }

    if(system("ip link set dev lo up") != EXIT_SUCCESS) {
        return CONTAINER_ERROR_NET_IFCONFIG;
    }

    if(system("ip link set dev eth0 up") != EXIT_SUCCESS) {
        return CONTAINER_ERROR_NET_IFCONFIG;
    }

    if(system("ip addr add 10.0.15.2 dev eth0") != EXIT_SUCCESS) {
        return CONTAINER_ERROR_NET_IFCONFIG;
    }

    if(system("ip route add 10.0.15.0/30 dev eth0") != EXIT_SUCCESS) {
        return CONTAINER_ERROR_NET_IFCONFIG;
    }

    if(system("ip route add default via 10.0.15.1") != EXIT_SUCCESS) {
        return CONTAINER_ERROR_NET_IFCONFIG;
    }

    container_error_t error;
    if((error = container_signaling_sync_send_fd(container, &tap_fd)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if(close(tap_fd) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_networking_initialize_parent(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(!container->networking_enabled) {
        return CONTAINER_ERROR_OKAY;
    }

    if(container->network_relay != NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    container_error_t error;

    int tap_fd;
    if((error = container_signaling_sync_recv_fd(container, &tap_fd)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    ip_addr_t ip;
    ip_addr_t netmask;

    IP4_ADDR(&ip, 10,0,15,1);
    IP4_ADDR(&netmask, 255,255,255,252);

    if((container->network_relay = network_relay_spawn(tap_fd, &ip, &netmask, container->port_mapping_count, container->port_mappings)) == NULL) {
        return CONTAINER_ERROR_NET_RELAY;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_networking_set_hostname(container_t *container, const char *hostname) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_ARG;
    }

    if(hostname == NULL) {
        return CONTAINER_ERROR_ARG;
    }

    container->hostname = hostname;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_networking_set_enabled(container_t *container, bool networking_enabled) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_ARG;
    }

    container->networking_enabled = networking_enabled;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_networking_set_port_mappings(container_t *container, size_t port_mapping_count, port_mapping_t *port_mappings) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_ARG;
    }

    container->port_mapping_count = port_mapping_count;
    container->port_mappings = port_mappings;

    return CONTAINER_ERROR_OKAY;
}