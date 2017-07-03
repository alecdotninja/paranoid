#ifndef PARANOID_NETWORKING_H
#define PARANOID_NETWORKING_H

#include "container.h"

void container_initialize_network_namespace(container_t *container);
void container_spawn_network_relay(container_t *container);

#endif //PARANOID_NETWORKING_H
