//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_SPAWN_H
#define PARANOID_SPAWN_H

#include "container.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

void container_spawn_child(container_t *container, int (*container_main) (container_t *container));

#endif //PARANOID_SPAWN_H
