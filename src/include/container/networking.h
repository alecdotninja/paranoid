#ifndef PARANOID_NETWORKING_H
#define PARANOID_NETWORKING_H

#include "container.h"

container_error_t container_networking_set_enabled(container_t *container, bool networking_enabled);
container_error_t container_networking_set_hostname(container_t *container, const char *hostname);
container_error_t container_networking_set_port_mappings(container_t *container, size_t port_mapping_count, port_mapping_t *port_mappings);

container_error_t container_networking_initialize_child(container_t *container);
container_error_t container_networking_initialize_parent(container_t *container);

#endif //PARANOID_NETWORKING_H
