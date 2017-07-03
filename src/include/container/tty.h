//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_TTY_H
#define PARANOID_TTY_H

#include "container.h"

void container_child_setup_tty(container_t *container);
void container_spawn_tty_relay(container_t *container);

#endif //PARANOID_TTY_H
