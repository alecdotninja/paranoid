#ifndef PARANOID_FS_H
#define PARANOID_FS_H

#include "container.h"

container_error_t container_set_root_path(container_t *container, const char *root_path);

container_error_t container_fs_namespace_bind_mount(const char *source_path, const char *destination_path, mode_t mode);
container_error_t container_fs_namespace_initialize(container_t *container);

#endif //PARANOID_FS_H
