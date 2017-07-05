#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <stropts.h>
#include <pty.h>
#include <utmp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "lwipopts.h"
#include <lwip/timeouts.h>
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include "container/networking.h"
#include "container/plumbing.h"
#include "container/signaling.h"

int open_tun() {
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

    int tun_fd;
    if((tun_fd = open_tun()) < 0) {
        fprintf(stderr, "[!] Failed to create eth0\n");
        exit(EXIT_FAILURE);
    }

    if(send_fd(container->child_signaling_fd, tun_fd) < 0) {
        fprintf(stderr, "[!] Failed to send eth0 outside of the container\n");
        exit(EXIT_FAILURE);
    }

    if(receive_message(container->child_signaling_fd) < 0) {
        fprintf(stderr, "[!] Failed to wait for parent to take ownership of eth0\n");
        exit(EXIT_FAILURE);
    }

    if(close(tun_fd) < 0) {
        fprintf(stderr, "[!] Failed to abandon eth0\n");
        exit(EXIT_FAILURE);
    }

    system("ip link set dev lo up");
    system("ip link set dev eth0 up");
    system("ip addr add 10.0.15.2 dev eth0");
    system("ip route add 10.0.15.0/24 dev eth0");
    system("ip route add default via 10.0.15.1");
}

struct tcp_pcb *tcp_listener = NULL;

err_t tcp_accepter(void *arg, struct tcp_pcb *tcp_client, err_t err) {
    if(err == ERR_OK) {
        tcp_accepted(tcp_listener);

        fprintf(stderr, "[!] Client accepted!\n");
    }else{
        fprintf(stderr, "[!] Error in tcp_accepter (%i).\n", err);
    }
}
//
//void *tcp_main(void *data) {
//    struct netif* netif = data;
//
//    while(1) {
//        tunif_input(netif);
//        sys_check_timeouts();
//    }
//
//    return NULL;
//}

void container_spawn_network_relay(container_t *container) {
//    struct netif *netif = &container->netif;
//    struct tunif *tunif = &container->tunif;

    int tun_fd;
    if((tun_fd = recv_fd(container->parent_signaling_fd)) < 0) {
        fprintf(stderr, "[!] Cannot claim eth0.\n");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    if(ioctl(tun_fd, SIOCGIFHWADDR, (void *)&ifr) < 0) {
        fprintf(stderr, "[!] Cannot get ifreq from eth0.\n");
        exit(EXIT_FAILURE);
    }

    /* display result */
    printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           (unsigned char)ifr.ifr_hwaddr.sa_data[0],
           (unsigned char)ifr.ifr_hwaddr.sa_data[1],
           (unsigned char)ifr.ifr_hwaddr.sa_data[2],
           (unsigned char)ifr.ifr_hwaddr.sa_data[3],
           (unsigned char)ifr.ifr_hwaddr.sa_data[4],
           (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

//    spawn_relay(tun_fd, 2);

//    fprintf(stderr, "[*] tunfd = %i\n", tun_fd);
//
//    tunif->fd = tun_fd;
//
//    lwip_init();
//
//    ip4_addr_t addr;
//    IP4_ADDR(&addr, 10,0,15,1);
//
//    ip4_addr_t netmask;
//    IP4_ADDR(&netmask, 255,255,255,0);
//
//    ip4_addr_t gw;
//    ip4_addr_set_any(&gw);
//
//    if(netif_add(netif, &addr, &netmask, &gw, tunif, tunif_init, ip_input) == NULL) {
//        fprintf(stderr, "[!] Failed to add eth0 to lwip tcp stack\n");
//        exit(EXIT_FAILURE);
//    }

//    netif_set_up(netif);

    // not sure what this does, but it seems to have been removed. :\
//    netif_set_pretend_tcp(netif, 1);

//    netif_set_default(netif);

//    struct tcp_pcb *tcp_pcb;
//
//    if((tcp_pcb = tcp_new()) == NULL) {
//        fprintf(stderr, "[!] Failed to create tcp stack\n");
//        exit(EXIT_FAILURE);
//    }

//    tcp_bind_netif(tcp_pcb, netif);
//
//    if(tcp_listener != NULL) {
//        fprintf(stderr, "[!] Time to refactor so that tcp_listener isn't global. ;)\n");
//        exit(EXIT_FAILURE);
//    }
//
//    if((tcp_listener = tcp_listen(tcp_pcb)) == NULL) {
//        fprintf(stderr, "[!] Failed to listen.\n");
//        exit(EXIT_FAILURE);
//    }

//    pthread_t thread;

//    pthread_create(&thread, NULL, tcp_main, netif);

//    tcp_accept(tcp_pcb, tcp_accepter);

    send_message(container->parent_signaling_fd, 0);
}
