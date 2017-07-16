#ifndef PARANOID_INIT_H
#define PARANOID_INIT_H

#include "container.h"

container_error_t container_set_init(container_t *container, int argc, char ** argv);

container_error_t container_init_exec(container_t *container);

#endif //PARANOID_INIT_H
