//
// Created by alec.larsen on 7/2/17.
//

#ifndef PARANOID_USERNS_H
#define PARANOID_USERNS_H

#include "container.h"

container_error_t container_user_namespace_initialize_parent(container_t *container);
container_error_t container_user_namespace_initialize_child(container_t *container);

#endif //PARANOID_USERNS_H
