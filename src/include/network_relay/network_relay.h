//
// Created by alec.larsen on 7/5/17.
//

#ifndef PARANOID_NETWORK_RELAY_H
#define PARANOID_NETWORK_RELAY_H

#include <netif/tapif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <pthread.h>
#include <stdbool.h>

typedef enum {
    PORT_MAPPING_PROTOCOL_TCP = 0,
    PORT_MAPPING_PROTOCOL_UDP = 1
} port_mapping_protocol_t;

typedef struct port_mapping {
    port_mapping_protocol_t protocol;

    int socket_fd;

    u16_t local_port;

    ip_addr_t remote_address;
    u16_t remote_port;
} port_mapping_t;

typedef struct network_relay_tcp_connection {
    struct network_relay_tcp_connection *next;

    bool is_connected;

    int socket_fd;
    struct tcp_pcb *pcb;

    char buffer[TCP_SND_BUF];
    u16_t buffer_size;
    bool is_flushed;
} network_relay_tcp_connection_t;

typedef struct network_relay_udp_connection {
    struct network_relay_udp_connection *next;

    ip_addr_t local_address;
    u16_t local_port;
    ip_addr_t remote_address;
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
    network_relay_tcp_connection_t *tcp_connection;

    port_mapping_t *port_mappings;
    size_t port_mapping_count;
} network_relay_t;

network_relay_t *network_relay_spawn(int tap_fd, const ip_addr_t *ip, const ip_addr_t *netmask, size_t port_mapping_count, port_mapping_t *port_mappings);

#endif //PARANOID_NETWORK_RELAY_H
