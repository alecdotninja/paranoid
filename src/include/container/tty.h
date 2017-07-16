//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_TTY_H
#define PARANOID_TTY_H

#include "container.h"

container_error_t container_tty_initialize_child(container_t *container);
container_error_t container_tty_initialize_parent(container_t *container);

#endif //PARANOID_TTY_H
