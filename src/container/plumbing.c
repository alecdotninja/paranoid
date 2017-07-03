#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <pty.h>
#include <pthread.h>

#include "container/plumbing.h"

int copy_file(const char * source_file_path, const char * destination_file_path) {
    int source_file_fd = open(source_file_path, O_RDONLY);

    if(source_file_fd < 0) {
        return -1;
    }

    int destination_file_fd = open(destination_file_path, O_CREAT | O_WRONLY);

    if(destination_file_fd < 0) {
        return -2;
    }

    char buffer[BUFSIZ];
    ssize_t size;

    while((size = read(source_file_fd, buffer, sizeof(buffer))) > 0) {
        if(write(destination_file_fd, buffer, (size_t)size) < size) {
            return -3;
        }
    }

    close(source_file_fd);
    close(destination_file_fd);

    return 0;
}

void *do_relay(void *data) {
    relay_t *relay = data;

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

relay_t *spawn_relay(int in_fd, int out_fd) {
    relay_t *relay = malloc(sizeof(relay_t));
    relay->in_fd = in_fd;
    relay->out_fd = out_fd;

    if(pthread_create(&relay->relay_thread, NULL, do_relay, relay) < 0) {
        free(relay);
        relay = NULL;
    }

    return relay;
}