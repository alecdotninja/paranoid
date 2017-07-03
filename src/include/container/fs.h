#ifndef PARANOID_FS_H
#define PARANOID_FS_H

#include "container.h"
#include "syscall.h"

#define pivot_root(new_root, put_old_root) syscall(SYS_pivot_root, new_root, put_old_root)

void container_initialize_fs_namespace(container_t *container);

#endif //PARANOID_FS_H
