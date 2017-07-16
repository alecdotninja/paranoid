#ifndef PARANOID_PLUMBING_H
#define PARANOID_PLUMBING_H

#include <pthread.h>

typedef struct fd_relay {
    pthread_t fd_relay_thread;

    int in_fd;
    int out_fd;
} fd_relay_t;

fd_relay_t *fd_relay_spawn(int in_fd, int out_fd);

#endif //PARANOID_PLUMBING_H
