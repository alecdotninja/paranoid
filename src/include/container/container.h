#ifndef PARANOID_CONTAINER_H
#define PARANOID_CONTAINER_H

#include "sched.h"

typedef struct __container {
    pid_t child_pid;
    int parent_signaling_fd;
    int child_signaling_fd;

    const char *hostname;
    const char *root_path;
    int init_argc;
    char **init_argv;

    int exit_code;
} container_t;

void container_start(container_t *container);
void container_wait(container_t *container);


#endif //PARANOID_CONTAINER_H