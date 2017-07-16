#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stropts.h>
#include <pty.h>
#include <container/fsns.h>

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

container_error_t container_tty_initialize_child(container_t *container) {
    container_error_t error;

    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    int master_fd, slave_fd;

    if(create_pty(&master_fd, &slave_fd) < 0) {
        return CONTAINER_ERROR_TTY;
    }

    if((error = container_fs_namespace_bind_mount("/dev/pts/0", "/dev/console", 600)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_signaling_sync_send_fd(container, &master_fd)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if(close(master_fd) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(setsid() < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(ioctl(slave_fd, TIOCSCTTY, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(isatty(STDIN_FILENO)) {
        if(dup2(slave_fd, STDIN_FILENO) < 0) {
            return CONTAINER_ERROR_SYSTEM;
        }
    }

    if(isatty(STDOUT_FILENO)) {
        if(dup2(slave_fd, STDOUT_FILENO) < 0) {
            return CONTAINER_ERROR_SYSTEM;
        }
    }

    if(isatty(STDERR_FILENO)) {
        if(dup2(slave_fd, STDERR_FILENO) < 0) {
            return CONTAINER_ERROR_SYSTEM;
        }
    }

    if(close(slave_fd) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_tty_initialize_parent(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->stdin_relay != NULL || container->stdout_relay != NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    container_error_t error;

    int tty_fd;
    if((error = container_signaling_sync_recv_fd(container, &tty_fd)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((container->stdin_relay  = fd_relay_spawn(STDIN_FILENO, tty_fd)) == NULL) {
        return CONTAINER_ERROR_TTY;
    }

    if((container->stdout_relay  = fd_relay_spawn(tty_fd, STDOUT_FILENO)) == NULL) {
        return CONTAINER_ERROR_TTY;
    }

    return CONTAINER_ERROR_OKAY;
}
