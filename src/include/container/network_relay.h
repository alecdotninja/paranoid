//
// Created by alec.larsen on 7/5/17.
//

#ifndef PARANOID_NETWORK_RELAY_H
#define PARANOID_NETWORK_RELAY_H

#include <pthread.h>

typedef struct network_relay {
    pthread_t network_relay_thread;

    int tap_fd;
} network_relay_t;

network_relay_t *spawn_network_relay(int tap_fd);

#endif //PARANOID_NETWORK_RELAY_H
