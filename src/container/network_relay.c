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

#include "container/network_relay.h"


err_t network_relay_tcp_accept(void *data, struct tcp_pcb *connection, err_t err) {
//    network_relay_t *network_relay = data;

    const char *message = "Hello, world!\n";

    tcp_write(connection, message, sizeof(message), TCP_WRITE_FLAG_COPY);
    tcp_output(connection);
    tcp_close(connection);

    return ERR_OK;
}

void *do_network_relay(void *data) {
    network_relay_t *network_relay = data;

    lwip_init();

    int tap_fd = network_relay->tap_fd;

    struct tapif tapif;
    tapif.fd = tap_fd;

    struct netif netif;

    ip4_addr_t ipaddr, netmask;

    IP4_ADDR(&ipaddr, 10,0,15,1);
    IP4_ADDR(&netmask, 255,255,255,0);

    netif_add(&netif, &ipaddr, &netmask, NULL, &tapif, tapif_init, ethernet_input);
    netif_set_default(&netif);
    netif_set_up(&netif);

    struct tcp_pcb *listener = tcp_new();
    tcp_arg(listener, network_relay);
    tcp_bind(listener, IP_ADDR_ANY, 0);
    listener = tcp_listen(listener);
    tcp_accept(listener, network_relay_tcp_accept);

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