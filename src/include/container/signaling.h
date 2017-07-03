//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_SIGNALING_H
#define PARANOID_SIGNALING_H

#include <stdlib.h>

#include "container.h"

#define FD_TRANSIT_CHECK (1337)

ssize_t send_fd(int socket_fd, int fd);
int recv_fd(int socket_fd);

int receive_message(int signaling_fd);
void send_message(int signaling_fd, int message);

void container_initialize_signaling_socket(container_t *container);
void container_finalize_signaling_socket_parent(container_t *container);
void container_finalize_signaling_socket_child(container_t *container);

#endif //PARANOID_SIGNALING_H
