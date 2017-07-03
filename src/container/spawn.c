#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

#include "container/spawn.h"

pid_t __attribute__((noinline)) spawn(int (*main) (void *), int flags, void *arg) {
    return clone(main, __builtin_frame_address(0), flags | SIGCHLD, arg);
}

void container_spawn_child(container_t *container, int (*container_main) (container_t *container)) {
    void *child_data = (void *)container;

    pid_t child_pid = spawn((int (*)(void *))container_main, CLONE_NEWCGROUP | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID, child_data);

    if(child_pid < 0) {
        fprintf(stderr, "[!] Cannot spawn child process. Perhaps your kernel does not support namespaces?\n");
        exit(EXIT_FAILURE);
    }

    container->child_pid = child_pid;
}
