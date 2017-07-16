//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_SIGNALING_H
#define PARANOID_SIGNALING_H

#include <stdlib.h>

#include "container.h"

container_error_t container_signaling_initialize_pre_spawn(container_t *container);
container_error_t container_signaling_initialize_parent(container_t *container);
container_error_t container_signaling_initialize_child(container_t *container);
container_error_t container_signaling_finalize(container_t *container);
container_error_t container_signaling_sync(container_t *container);
container_error_t container_signaling_sync_send_fd(container_t *container, int *fd);
container_error_t container_signaling_sync_recv_fd(container_t *container, int *fd);

#endif //PARANOID_SIGNALING_H
