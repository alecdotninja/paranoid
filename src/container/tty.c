#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stropts.h>
#include <pty.h>

#include "container/tty.h"
#include "plumbing/fd_relay.h"
#include "container/signaling.h"

// based on openpty from libc with extra stuff removed
static int create_pty(int *master_fd, int *slave_fd) {
    if((*master_fd = getpt()) < 0) {
        return -1;
    }

    if(grantpt(*master_fd) < 0) {
        close(*master_fd);
        return -2;
    }

    if(unlockpt(*master_fd) < 0) {
        close(*master_fd);
        return -3;
    }

    char pts_name[512];
    if(ptsname_r(*master_fd, pts_name, sizeof(pts_name)) < 0) {
        close(*master_fd);
        return -4;
    }

    if((*slave_fd = open(pts_name,  O_RDWR | O_NOCTTY)) < 0) {
        close(*master_fd);
        return -5;
    }

    return 0;
}

void container_child_setup_tty(container_t *container) {
    int master_fd, slave_fd;

    if(create_pty(&master_fd, &slave_fd) < 0) {
        fprintf(stderr, "[!] Failed to create pty.\n");
        exit(EXIT_FAILURE);
    }

//    link_dev("/dev/pts/0", "/dev/console", 600);
//    link_dev("/dev/pts/0", "/dev/tty0", 600);

    if(send_fd(container->child_signaling_fd, master_fd) < 0) {
        fprintf(stderr, "[!] Failed to send pty to parent.\n");
        exit(EXIT_FAILURE);
    }

    if(receive_message(container->child_signaling_fd) < 0) {
        fprintf(stderr, "[!] Parent did not accept tty.\n");
        exit(EXIT_FAILURE);
    }

    close(master_fd);

    setsid();

    if(ioctl(slave_fd, TIOCSCTTY, NULL) < 0) {
        fprintf(stderr, "[!] Failed set tty to leader.\n");
        exit(EXIT_FAILURE);
    }

    if(isatty(STDIN_FILENO)) {
        if(dup2(slave_fd, STDIN_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDIN.\n");
            exit(EXIT_FAILURE);
        }
    }

    if(isatty(STDOUT_FILENO)) {
        if(dup2(slave_fd, STDOUT_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDOUT.\n");
            exit(EXIT_FAILURE);
        }
    }

    if(isatty(STDERR_FILENO)) {
        if(dup2(slave_fd, STDERR_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDERR.\n");
            exit(EXIT_FAILURE);
        }
    }

    close(slave_fd);
}

void container_spawn_tty_relay(container_t *container) {
    int tty_fd;
    if((tty_fd = recv_fd(container->parent_signaling_fd)) < 0) {
        fprintf(stderr, "[!] Failed to receive tty.\n");
        exit(EXIT_FAILURE);
    }

    spawn_fd_relay(STDIN_FILENO, tty_fd);
    spawn_fd_relay(tty_fd, STDOUT_FILENO);

    send_message(container->parent_signaling_fd, 0);
}
