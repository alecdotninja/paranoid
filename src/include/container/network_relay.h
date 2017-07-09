//
// Created by alec.larsen on 7/5/17.
//

#ifndef PARANOID_NETWORK_RELAY_H
#define PARANOID_NETWORK_RELAY_H

#include <netif/tapif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <pthread.h>

typedef struct network_relay_udp_connection {
    struct network_relay_udp_connection *next;

    u32_t local_address;
    u16_t local_port;
    u32_t remote_address;
    u16_t remote_port;

    int socket_fd;
    struct udp_pcb *pcb;

    time_t last_used_at;
} network_relay_udp_connection_t;

typedef struct network_relay {
    pthread_t network_relay_thread;

    struct tapif tapif;
    struct netif netif;

    ip4_addr_t ip;
    ip4_addr_t netmask;

    struct tcp_pcb *tcp_listener;
    struct udp_pcb *udp_listener;

    network_relay_udp_connection_t *udp_connection;
} network_relay_t;

network_relay_t *spawn_network_relay(int tap_fd, in_addr_t ip, in_addr_t netmask);

#endif //PARANOID_NETWORK_RELAY_H
