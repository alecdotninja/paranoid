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

#include "container/network_relay.h"


err_t network_relay_tcp_accept(void *data, struct tcp_pcb *connection, err_t err) {
//    network_relay_t *network_relay = data;

    char buffer[2048];

    snprintf(buffer, sizeof(buffer), "Hello there from %i.%i.%i.%i:%i!\n",
             ip4_addr1(&connection->local_ip),
             ip4_addr2(&connection->local_ip),
             ip4_addr3(&connection->local_ip),
             ip4_addr4(&connection->local_ip),
             connection->local_port
    );

    tcp_write(connection, buffer, strlen(buffer), TCP_WRITE_FLAG_COPY);
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

    ip4_addr_t ipaddr, netmask, gw;

    IP4_ADDR(&gw, 10,0,15,1);
    IP4_ADDR(&ipaddr, 10,0,15,1);
    IP4_ADDR(&netmask, 255,255,255,0);

    netif_add(&netif, &ipaddr, &netmask, &gw, &tapif, tapif_init, ethernet_input);
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