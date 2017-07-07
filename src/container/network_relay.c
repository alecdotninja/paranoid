#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <pty.h>
#include <pthread.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <netif/tapif.h>
#include <netif/etharp.h>
#include <lwip/timeouts.h>
#include <lwip/tcp.h>
#include <memory.h>
#include <lwip/udp.h>

#include "container/network_relay.h"


err_t network_relay_tcp_accept(void *data, struct tcp_pcb *connection, err_t err) {
    network_relay_t *network_relay = data;

    fprintf(stderr, "[*] TCP %i.%i.%i.%i:%i\n", ip4_addr1(&connection->local_ip), ip4_addr2(&connection->local_ip),
            ip4_addr3(&connection->local_ip), ip4_addr4(&connection->local_ip), connection->local_port);

    tcp_close(connection);

    return ERR_OK;
}

void network_relay_udp_recv(void *data, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *remote_ip, u16_t remote_port, const ip_addr_t *local_ip, u16_t local_port) {
    network_relay_t *network_relay = data;

    pbuf_free(p);

    fprintf(stderr, "[*] UDP %i.%i.%i.%i:%i\n", ip4_addr1(local_ip), ip4_addr2(local_ip),
            ip4_addr3(local_ip), ip4_addr4(local_ip), local_port);
}

void network_relay_init_tcp(network_relay_t *network_relay) {
    struct tcp_pcb *tcp_listener = tcp_new();
    tcp_arg(tcp_listener, network_relay);
    tcp_bind(tcp_listener, IP_ADDR_ANY, 0);
    tcp_listener = tcp_listen(tcp_listener);
    tcp_accept(tcp_listener, network_relay_tcp_accept);
}

void network_relay_init_upd(network_relay_t *network_relay) {
    struct udp_pcb *udp_listener = udp_new();
    udp_bind(udp_listener, IP_ADDR_ANY, 0);
    udp_recv(udp_listener, network_relay_udp_recv, network_relay);
}

void *do_network_relay(void *data) {
    network_relay_t *network_relay = data;

    lwip_init();

    int tap_fd = network_relay->tap_fd;

    struct tapif tapif;
    tapif.fd = tap_fd;

    struct netif netif;

    ip4_addr_t ipaddr, netmask, gw;

    IP4_ADDR(&gw, 10,0,15,1);
    IP4_ADDR(&ipaddr, 10,0,15,1);
    IP4_ADDR(&netmask, 255,255,255,0);

    netif_add(&netif, &ipaddr, &netmask, &gw, &tapif, tapif_init, ethernet_input);
    netif_set_default(&netif);
    netif_set_up(&netif);

    network_relay_init_tcp(network_relay);
    network_relay_init_upd(network_relay);

    while (1) {
        tapif_select(&netif);
        sys_check_timeouts();
    }

    return NULL;
}

network_relay_t *spawn_network_relay(int tap_fd) {
    network_relay_t *network_relay = malloc(sizeof(network_relay_t));
    network_relay->tap_fd = tap_fd;

    if(pthread_create(&network_relay->network_relay_thread, NULL, do_network_relay, network_relay) < 0) {
        free(network_relay);
        network_relay = NULL;
    }

    return network_relay;
}