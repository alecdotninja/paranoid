#ifndef PARANOID_PLUMBING_H
#define PARANOID_PLUMBING_H

#include <pthread.h>

typedef struct relay {
    pthread_t relay_thread;

    int in_fd;
    int out_fd;
} relay_t;

int copy_file(const char * source_file_path, const char * destination_file_path);
relay_t *spawn_relay(int in_fd, int out_fd);

#endif //PARANOID_PLUMBING_H
