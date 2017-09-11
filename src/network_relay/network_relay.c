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
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>

#include "network_relay/network_relay.h"

static void load_inet_into_sockaddr(struct sockaddr_in *sockaddr, const ip_addr_t *ip, u16_t port) {
    assert(IP_IS_V4_VAL(ip));

    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = ip->addr;
    sockaddr->sin_port = htons(port);
}

static void load_sockaddr_into_inet(ip_addr_t *ip, u16_t *port, const struct sockaddr_in *sockaddr) {
    assert(sockaddr->sin_family == AF_INET);

    *port = ntohs(sockaddr->sin_port);
    ip->addr = sockaddr->sin_addr.s_addr;
}

static void network_relay_free_tcp_connection(network_relay_t *network_relay, network_relay_tcp_connection_t *target_tcp_connection);

static err_t network_relay_tcp_connected(network_relay_t *network_relay, struct tcp_pcb *pcb, err_t err) {
    network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

    while(tcp_connection != NULL) {
        if(tcp_connection->pcb == pcb) {
            break;
        }

        tcp_connection = tcp_connection->next;
    }

    if(tcp_connection == NULL) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    if(err == ERR_OK) {
        tcp_connection->is_connected = true;
    }else{
        network_relay_free_tcp_connection(network_relay, tcp_connection);
    }

    return ERR_OK;
}

static network_relay_tcp_connection_t * network_relay_alloc_tcp_connection(network_relay_t *network_relay, int socket_fd, struct tcp_pcb *pcb) {
    if(pcb == NULL && socket_fd < 0 || pcb != NULL && socket_fd >= 0) { // we need something to go on
        return NULL;
    }

    bool is_connected = true;

    if(pcb == NULL) {
        assert(socket_fd >= 0);

        struct sockaddr_in local_sockaddr = { 0 };
        socklen_t local_socklen = sizeof(struct sockaddr_in);
        if(getpeername(socket_fd, (struct sockaddr*)&local_sockaddr, &local_socklen) < 0) {
            return NULL;
        }

        ip_addr_t local_address;
        u16_t local_port;
        load_sockaddr_into_inet(&local_address, &local_port, &local_sockaddr);

        ip_addr_t remote_address;
        u16_t remote_port;

        IP4_ADDR(&remote_address, 10,0,15,2);
        remote_port = 12345;


        if((pcb = tcp_new()) == NULL) {
            return NULL;
        }

        tcp_arg(pcb, network_relay);

        if(tcp_bind(pcb, &local_address, local_port) != ERR_OK) {
            // TODO: free the pcb?
            return NULL;
        }

        if(tcp_connect(pcb, &remote_address, remote_port, (tcp_connected_fn)network_relay_tcp_connected) != ERR_OK) {
            // TODO: free the pcb?
            return NULL;
        }

        is_connected = false;
    }


    if(socket_fd < 0) {
        assert(pcb != NULL);

        struct sockaddr_in sockaddr = { 0 };

        if(ip_addr_cmp(&pcb->local_ip, &network_relay->ip)) {
            ip_addr_t loopback;
            IP4_ADDR(&loopback, 127,0,0,1);

            load_inet_into_sockaddr(&sockaddr, &loopback, pcb->local_port);
        }else{
            load_inet_into_sockaddr(&sockaddr, &pcb->local_ip, pcb->local_port);
        }

        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sockaddr.sin_addr), str, INET_ADDRSTRLEN);

        if((socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            return NULL;
        }

        if(connect(socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
            close(socket_fd);
            return NULL;
        }

        is_connected = true;
    }

    network_relay_tcp_connection_t *tcp_connection = calloc(1, sizeof(network_relay_tcp_connection_t));

    if(tcp_connection != NULL) {
        tcp_connection->is_connected = is_connected;

        tcp_connection->socket_fd = socket_fd;
        tcp_connection->pcb = pcb;
        tcp_connection->buffer_size = 0;
        tcp_connection->is_flushed = true;

        tcp_connection->next = network_relay->tcp_connection;
        network_relay->tcp_connection = tcp_connection;
    }

    return tcp_connection;
}

static void network_relay_free_tcp_connection(network_relay_t *network_relay, network_relay_tcp_connection_t *target_tcp_connection) {
    network_relay_tcp_connection_t *prev_tcp_connection = NULL;
    network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

    while(tcp_connection != NULL) {
        network_relay_tcp_connection_t *next_tcp_connection = tcp_connection->next;

        if(tcp_connection == target_tcp_connection) {
            if(prev_tcp_connection == NULL) {
                network_relay->tcp_connection = tcp_connection->next;
            }else{
                prev_tcp_connection->next = tcp_connection->next;
            }
        }else{
            prev_tcp_connection = tcp_connection;
        }

        tcp_connection = next_tcp_connection;
    }

    close(target_tcp_connection->socket_fd);
    tcp_close(target_tcp_connection->pcb);
    free(target_tcp_connection);
}

static err_t network_relay_tcp_recv_pcb(network_relay_t *network_relay, struct tcp_pcb *pcb, struct pbuf *pbuf, err_t err) {
    if(err == ERR_OK) {
        network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

        while(tcp_connection != NULL) {
            if(tcp_connection->pcb == pcb) {
                break;
            }

            tcp_connection = tcp_connection->next;
        }

        if(tcp_connection == NULL) {
            tcp_abort(pcb);
            return ERR_ABRT;
        }

        if(pbuf != NULL) {
            ssize_t length;

            if((length = write(tcp_connection->socket_fd, pbuf->payload, pbuf->len)) > 0) {
                tcp_recved(pcb, (u16_t)length);
                pbuf_free(pbuf);

                return ERR_OK;
            }else{
                return ERR_MEM;
            }
        }else{
            network_relay_free_tcp_connection(network_relay, tcp_connection);
            return ERR_OK;
        }
    }else{
        return ERR_VAL;
    }
}

static err_t network_relay_tcp_accept(network_relay_t *network_relay, struct tcp_pcb *pcb, err_t err) {
    if(pcb != NULL && err == ERR_OK) {
        network_relay_tcp_connection_t *tcp_connection = network_relay_alloc_tcp_connection(network_relay, -1, pcb);

        if(tcp_connection != NULL) {
            tcp_recv(pcb, (tcp_recv_fn)network_relay_tcp_recv_pcb);
            return ERR_OK;
        }else{
            tcp_abort(pcb);
            return ERR_ABRT;
        }
    }else{
        return ERR_VAL;
    }
}

static network_relay_udp_connection_t * network_relay_alloc_udp_connection(network_relay_t *network_relay,
                                                                    ip_addr_t local_ip, u16_t local_port,
                                                                    ip_addr_t remote_ip, u16_t remote_port,
                                                                    int socket_fd, struct udp_pcb *pcb) {
    assert(pcb != NULL); // for now...

    if(socket_fd < 0) {
        assert(pcb != NULL);

        struct sockaddr_in sockaddr = { 0 };

        if(ip_addr_cmp(&local_ip, &network_relay->ip)) {
            ip_addr_t loopback;
            IP4_ADDR(&loopback, 127,0,0,1);

            load_inet_into_sockaddr(&sockaddr, &loopback, local_port);
        }else{
            load_inet_into_sockaddr(&sockaddr, &local_ip, local_port);
        }

        if((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            return NULL;
        }

        if(connect(socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
            close(socket_fd);
            return NULL;
        }
    }

    network_relay_udp_connection_t *udp_connection = calloc(1, sizeof(network_relay_udp_connection_t));

    if(udp_connection != NULL) {
        udp_connection->local_address = local_ip;
        udp_connection->local_port = local_port;
        udp_connection->remote_address = remote_ip;
        udp_connection->remote_port = remote_port;

        udp_connection->socket_fd = socket_fd;
        udp_connection->pcb = pcb;

        udp_connection->last_used_at = time(NULL);

        // add it to the front of the list
        udp_connection->next = network_relay->udp_connection;
        network_relay->udp_connection = udp_connection;
    }

    return udp_connection;
}

static void network_relay_udp_connection_recv_socket(network_relay_udp_connection_t *udp_connection, void *payload, u16_t length) {
    udp_connection->last_used_at = time(NULL);

    struct udp_pcb *pcb = udp_connection->pcb;

    ip_addr_t local_ip = udp_connection->local_address;
    u16_t local_port = udp_connection->local_port;

    ip_addr_t remote_ip = udp_connection->remote_address;
    u16_t remote_port = udp_connection->remote_port;

    struct pbuf *pbuf = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);

    if(pbuf != NULL) {
        pbuf_take(pbuf, payload, length);

        struct netif *netif;

        if(IP_IS_ANY_TYPE_VAL(pcb->local_ip)) {
            /* Don't call ip_route() with IP_ANY_TYPE */
            netif = ip_route(IP46_ADDR_ANY(IP_GET_TYPE(&pcb->remote_ip)), &pcb->remote_ip);
        } else {
            netif = ip_route(&pcb->local_ip, &pcb->remote_ip);
        }

        if(udp_sendto_if_src_port(pcb, pbuf, &remote_ip, remote_port, netif, &local_ip, local_port) < 0) {
            fprintf(stderr, "[!] UDP dropped message (this should never happen)\n");
        }

        pbuf_free(pbuf);
    }
}

static void network_relay_udp_connection_recv_pcb(network_relay_udp_connection_t *udp_connection, void *payload, size_t length) {
    udp_connection->last_used_at = time(NULL);

    if(write(udp_connection->socket_fd, payload, length) < 0) {
        fprintf(stderr, "[!] UDP dropped message (this should never happen)\n");
    }
}

static void network_relay_udp_recv_pcb(network_relay_t *network_relay, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *remote_ip, u16_t remote_port, const ip_addr_t *local_ip, u16_t local_port) {
    network_relay_udp_connection_t *udp_connection = network_relay_alloc_udp_connection(network_relay, *local_ip, local_port, *remote_ip, remote_port, -1, pcb);

    if(udp_connection != NULL) {
        network_relay_udp_connection_recv_pcb(udp_connection, p->payload, p->len);
    }

    pbuf_free(p);
}

static void network_relay_free_udp_connection(network_relay_t *network_relay, network_relay_udp_connection_t *target_udp_connection) {
    network_relay_udp_connection_t *prev_udp_connection = NULL;
    network_relay_udp_connection_t *udp_connection = network_relay->udp_connection;

    while(udp_connection != NULL) {
        network_relay_udp_connection_t *next_udp_connection = udp_connection->next;

        if(udp_connection == target_udp_connection) {
            if(prev_udp_connection == NULL) {
                network_relay->udp_connection = udp_connection->next;
            }else{
                prev_udp_connection->next = udp_connection->next;
            }
        }else{
            prev_udp_connection = udp_connection;
        }

        udp_connection = next_udp_connection;
    }

    close(target_udp_connection->socket_fd);
    free(target_udp_connection);
}

static bool network_relay_tcp_connection_flush(network_relay_tcp_connection_t *tcp_connection) {
    err_t err;

    if(tcp_connection->buffer_size > 0) {
        if ((err = tcp_write(tcp_connection->pcb, tcp_connection->buffer, tcp_connection->buffer_size, TCP_WRITE_FLAG_COPY)) != ERR_MEM) {
            tcp_connection->buffer_size = 0;
            tcp_connection->is_flushed = false;
        }else{
            return false;
        }
    }

    if(!tcp_connection->is_flushed) {
        if((err = tcp_output(tcp_connection->pcb)) != ERR_MEM) {
            tcp_connection->is_flushed = true;
        }else{
            return false;
        }
    }

    return true;
}

static void network_relay_flush_tcp_connections(network_relay_t *network_relay) {
   network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

    while(tcp_connection != NULL) {
        network_relay_tcp_connection_t *next_tcp_connection = tcp_connection->next;

        if(tcp_connection->buffer_size > 0 || !tcp_connection->is_flushed) {
            network_relay_tcp_connection_flush(tcp_connection);
        }

        tcp_connection = next_tcp_connection;
    }
}

static void network_relay_prune_udp_connections(network_relay_t *network_relay) {
    time_t now = time(NULL);

    network_relay_udp_connection_t *udp_connection = network_relay->udp_connection;

    while(udp_connection != NULL) {
        network_relay_udp_connection_t *next_udp_connection = udp_connection->next;

        if(now - udp_connection->last_used_at > 30) {
            network_relay_free_udp_connection(network_relay, udp_connection);
        }

        udp_connection = next_udp_connection;
    }
}

static void network_relay_tcp_prepare_fd_set(network_relay_t *network_relay, fd_set *fd_set, int *max_fd) {
    network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

    while(tcp_connection != NULL) {
        network_relay_tcp_connection_t *next_tcp_connection = tcp_connection->next;

        if(tcp_connection->is_connected && tcp_connection->buffer_size == 0 && tcp_connection->is_flushed) { // there's no point waiting for data that we can't handle
            int socket_fd = tcp_connection->socket_fd;

            if(max_fd != NULL && socket_fd > *max_fd) {
                *max_fd = socket_fd;
            }

            FD_SET(socket_fd, fd_set);
        }

        tcp_connection = next_tcp_connection;
    }
}

static void network_relay_tcp_respond_fd_set(network_relay_t *network_relay, fd_set *fd_set) {
    network_relay_tcp_connection_t *tcp_connection = network_relay->tcp_connection;

    while(tcp_connection != NULL) {
        network_relay_tcp_connection_t *next_tcp_connection = tcp_connection->next;

        int socket_fd = tcp_connection->socket_fd;

        if(FD_ISSET(socket_fd, fd_set)) {
            assert(tcp_connection->buffer_size == 0 && tcp_connection->is_flushed);

            ssize_t length;

            if((length = recv(socket_fd, tcp_connection->buffer, sizeof(tcp_connection->buffer), 0)) > 0) {
                tcp_connection->buffer_size = (u16_t)length;
                network_relay_tcp_connection_flush(tcp_connection);
            }else{
                network_relay_free_tcp_connection(network_relay, tcp_connection);
            }
        }

        tcp_connection = next_tcp_connection;
    }
}

static void network_relay_udp_prepare_fd_set(network_relay_t *network_relay, fd_set *fd_set, int *max_fd) {
    network_relay_udp_connection_t *udp_connection = network_relay->udp_connection;

    while(udp_connection != NULL) {
        network_relay_udp_connection_t *next_udp_connection = udp_connection->next;

        int socket_fd = udp_connection->socket_fd;

        if(max_fd != NULL && socket_fd > *max_fd) {
            *max_fd = socket_fd;
        }

        FD_SET(socket_fd, fd_set);

        udp_connection = next_udp_connection;
    }
}

static void network_relay_udp_respond_fd_set(network_relay_t *network_relay, fd_set *fd_set) {
    network_relay_udp_connection_t *udp_connection = network_relay->udp_connection;

    while(udp_connection != NULL) {
        network_relay_udp_connection_t *next_udp_connection = udp_connection->next;

        int socket_fd = udp_connection->socket_fd;

        if(FD_ISSET(socket_fd, fd_set)) {
            char buffer[BUFSIZ];
            ssize_t length;

            if((length = recv(socket_fd, &buffer, sizeof(buffer), 0)) > 0) {
                network_relay_udp_connection_recv_socket(udp_connection, buffer, (u16_t)length);
            }else{
                network_relay_free_udp_connection(network_relay, udp_connection);
            }
        }

        udp_connection = next_udp_connection;
    }
}

static void network_relay_init_tcp(network_relay_t *network_relay) {
    struct tcp_pcb *tcp_listener = tcp_new();
    tcp_arg(tcp_listener, network_relay);
    tcp_bind(tcp_listener, IP_ADDR_ANY, 0);
    tcp_listener = tcp_listen(tcp_listener);
    tcp_accept(tcp_listener, (tcp_accept_fn)network_relay_tcp_accept);

    network_relay->tcp_listener = tcp_listener;
}

static void network_relay_init_upd(network_relay_t *network_relay) {
    struct udp_pcb *udp_listener = udp_new();
    udp_bind(udp_listener, IP_ADDR_ANY, 0);
    udp_recv(udp_listener, (udp_recv_fn)network_relay_udp_recv_pcb, network_relay);

    network_relay->udp_listener = udp_listener;
}

static void network_relay_port_mapping_forward_tcp(port_mapping_t *port_mapping) {
    struct sockaddr_in sockaddr = { 0 };
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    sockaddr.sin_port = htons(port_mapping->local_port);

    int socket_fd;
    if((socket_fd = socket(AF_INET, SOCK_STREAM , 0)) < 0 ||
            bind(socket_fd,(struct sockaddr *)&sockaddr , sizeof(sockaddr)) < 0 ||
            listen(socket_fd, 16) < 0) {
        fprintf(stderr, "[!] Failed to setup %hu -> %hu (tcp)", port_mapping->local_port, port_mapping->remote_port);
        return;
    }

    port_mapping->socket_fd = socket_fd;
}

static void network_relay_forward(network_relay_t *network_relay, port_mapping_t *port_mapping) {
    switch(port_mapping->protocol) {
        case PORT_MAPPING_PROTOCOL_TCP:
            network_relay_port_mapping_forward_tcp(port_mapping);
            break;

        case PORT_MAPPING_PROTOCOL_UDP:
//            network_relay_forward_udp(network_relay, port_mapping);
            break;
    }
}

static void network_relay_forwarding_prepare_fd_set(network_relay_t *network_relay, fd_set *fd_set, int *max_fd) {
    for(size_t index = 0; index < network_relay->port_mapping_count; index++) {
        port_mapping_t *port_mapping = &network_relay->port_mappings[index];

        if(port_mapping->protocol == PORT_MAPPING_PROTOCOL_TCP) {
            if(max_fd != NULL && port_mapping->socket_fd > *max_fd) {
                *max_fd = port_mapping->socket_fd;
            }

            FD_SET(port_mapping->socket_fd, fd_set);
        }
    }
}

void network_relay_forwarding_accept_tcp(network_relay_t *network_relay, port_mapping_t *port_mapping) {
    struct sockaddr_in sockaddr = { 0 };
    socklen_t socklen;

    int socket_fd;
    if((socket_fd = accept(port_mapping->socket_fd, (struct sockaddr *)&sockaddr, &socklen)) < 0) {
        fprintf(stderr, "[!] Failed to accept connection (syscall).\n");
        return;
    }

    network_relay_tcp_connection_t *tcp_connection;
    if((tcp_connection = network_relay_alloc_tcp_connection(network_relay, socket_fd, NULL)) == NULL) {
        // failed to accept internally
        fprintf(stderr, "[!] Failed to accept connection (internal).\n");
        close(socket_fd);
        return;
    }
}

static void network_relay_forwarding_respond_fd_set(network_relay_t *network_relay, fd_set *fd_set) {
    for(size_t index = 0; index < network_relay->port_mapping_count; index++) {
        port_mapping_t *port_mapping = &network_relay->port_mappings[index];

        if(port_mapping->protocol == PORT_MAPPING_PROTOCOL_TCP) {
            if(FD_ISSET(port_mapping->socket_fd, fd_set)) {
                network_relay_forwarding_accept_tcp(network_relay, port_mapping);
            }
        }
    }
}

static void network_relay_init_forwarding(network_relay_t *network_relay) {
    for(size_t index = 0; index < network_relay->port_mapping_count; index++) {
        port_mapping_t *port_mapping = &network_relay->port_mappings[index];

        port_mapping->socket_fd = -1;
        network_relay_forward(network_relay, port_mapping);
    }
}

static void network_relay_init(network_relay_t *network_relay) {
    ip_addr_t *ip = &network_relay->ip;
    ip_addr_t *netmask = &network_relay->netmask;

    struct tapif *tapif = &network_relay->tapif;
    struct netif *netif = &network_relay->netif;

    lwip_init();

    netif_add(netif, ip, netmask, ip, tapif, tapif_init, ethernet_input);
    netif_set_default(netif);
    netif_set_up(netif);

    network_relay_init_tcp(network_relay);
    network_relay_init_upd(network_relay);

    network_relay_init_forwarding(network_relay);
}

static void network_relay_prepare_fd_set(network_relay_t *network_relay, fd_set *fd_set, int *max_fd) {
    tapif_prepare_fd_set(&network_relay->netif, fd_set, max_fd);
    network_relay_tcp_prepare_fd_set(network_relay, fd_set, max_fd);
    network_relay_udp_prepare_fd_set(network_relay, fd_set, max_fd);
    network_relay_forwarding_prepare_fd_set(network_relay, fd_set, max_fd);
}

static void network_relay_respond_fd_set(network_relay_t *network_relay, fd_set *fd_set) {
    tapif_respond_fd_set(&network_relay->netif, fd_set);
    network_relay_tcp_respond_fd_set(network_relay, fd_set);
    network_relay_udp_respond_fd_set(network_relay, fd_set);
    network_relay_forwarding_respond_fd_set(network_relay, fd_set);
}

static void *network_relay_loop(network_relay_t *network_relay) {
    network_relay_init(network_relay);

    while (1) {
        u32_t ms_until_next_timeout = sys_timeouts_sleeptime();

        if(ms_until_next_timeout == 0) { // the timeout needs to run now
            sys_check_timeouts();
            continue;
        }

        struct timeval tv;
        tv.tv_sec = ms_until_next_timeout / 1000;
        tv.tv_usec = (ms_until_next_timeout % 1000) * 1000;

        network_relay_prune_udp_connections(network_relay);
        network_relay_flush_tcp_connections(network_relay);

        fd_set fd_set;
        FD_ZERO(&fd_set);

        int max_fd = 0;

        network_relay_prepare_fd_set(network_relay, &fd_set, &max_fd);

        if(select(max_fd + 1, &fd_set, NULL, NULL, &tv) < 0) {
            if(errno == EINTR) {
                continue;
            }

            break;
        }

        network_relay_respond_fd_set(network_relay, &fd_set);
    }

    fprintf(stderr, "[!] The networking thread died.");
    exit(EXIT_FAILURE);

    return NULL;
}

network_relay_t *network_relay_spawn(int tap_fd, const ip_addr_t *ip, const ip_addr_t *netmask, size_t port_mapping_count, port_mapping_t *port_mappings) {
    network_relay_t *network_relay = calloc(1, sizeof(network_relay_t));

    network_relay->tapif.fd = tap_fd;

    network_relay->tcp_connection = NULL;
    network_relay->udp_connection = NULL;

    network_relay->port_mappings = port_mappings;
    network_relay->port_mapping_count = port_mapping_count;

    ip4_addr_set(&network_relay->ip, ip);
    ip4_addr_set(&network_relay->netmask, netmask);

    if(pthread_create(&network_relay->network_relay_thread, NULL, (void *)network_relay_loop, network_relay) < 0) {
        free(network_relay);
        network_relay = NULL;
    }

    return network_relay;
}