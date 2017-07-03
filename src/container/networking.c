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

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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
//
//    system("ip link set dev lo up");
//    system("ip link set dev eth0 up");
//    system("ip addr add 10.0.15.2 dev eth0");
//    system("ip route add 10.0.15.0/24 dev eth0");
//    system("ip route add default via 10.0.15.1");
}

void container_spawn_network_relay(container_t *container) {
    int tun_fd;
    if((tun_fd = recv_fd(container->parent_signaling_fd)) < 0) {
        fprintf(stderr, "[!] Cannot claim eth0.\n");
        exit(EXIT_FAILURE);
    }

    spawn_relay(tun_fd, STDOUT_FILENO);

    send_message(container->parent_signaling_fd, 0);
}
