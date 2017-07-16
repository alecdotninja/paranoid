#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stropts.h>
#include <pty.h>
#include <pthread.h>

#include "plumbing/fd_relay.h"

static void *do_relay(void *data) {
    fd_relay_t *relay = data;

    int in_fd = relay->in_fd;
    int out_fd = relay->out_fd;

    char buffer[BUFSIZ];
    ssize_t remaing, written;

    struct termios	termios;
    struct winsize	winsize;

    while(1) {
        if(isatty(in_fd) && isatty(out_fd)) {
            tcgetattr(in_fd, &termios);
            tcsetattr(out_fd, TCSANOW, &termios);

            ioctl(in_fd, TIOCGWINSZ, &winsize);
            ioctl(out_fd, TIOCSWINSZ, &winsize);
        }

        if((remaing = read(in_fd, &buffer, sizeof(buffer))) < 0) {
            break;
        }

        if(remaing == 0) {
            break;
        }

        while(remaing > 0) {
            if((written = write(out_fd, &buffer, (size_t)remaing)) < 0) {
                break;
            }

            remaing -= written;
        }
    }

    return NULL;
}

fd_relay_t *fd_relay_spawn(int in_fd, int out_fd) {
    fd_relay_t *relay = malloc(sizeof(fd_relay_t));
    relay->in_fd = in_fd;
    relay->out_fd = out_fd;

    if(pthread_create(&relay->fd_relay_thread, NULL, do_relay, relay) < 0) {
        free(relay);
        relay = NULL;
    }

    return relay;
}