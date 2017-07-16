//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_SPAWN_H
#define PARANOID_SPAWN_H

#include "container.h"

container_error_t container_spawn(container_t *container, container_error_t (*container_start_fn)(container_t *));
container_error_t container_spawn_kill(container_t *container);

#endif //PARANOID_SPAWN_H
