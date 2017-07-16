#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <zconf.h>
#include <sys/prctl.h>

#include "container/spawn.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

struct spawn_data {
    container_t *container;
    container_error_t (*container_start_fn)(container_t *);
};

static pid_t __attribute__((noinline)) spawn(int (*main) (void *), int flags, void *arg) {
    return clone(main, __builtin_frame_address(0), flags | SIGCHLD, arg);
}

static int spawn_main(struct spawn_data *spawn_data) {
    if(prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
        _exit(EXIT_FAILURE);
    }

    if(spawn_data == NULL) {
        _exit(EXIT_FAILURE);
    }

    container_t *container = spawn_data->container;

    if(container == NULL) {
        _exit(EXIT_FAILURE);
    }

    container_error_t (*container_start_fn)(container_t *) = spawn_data->container_start_fn;

    if(container_start_fn == NULL) {
        _exit(EXIT_FAILURE);
    }

    container_error_t error;
    if((error = container_start_fn(container)) != CONTAINER_ERROR_OKAY) {
        // TODO: Get the error back out to the parent process
        _exit(EXIT_FAILURE);
    }

    _exit(EXIT_SUCCESS);
}

container_error_t container_spawn(container_t *container, container_error_t (*container_start_fn)(container_t *)) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->init_pid > 0) {
        return CONTAINER_ERROR_SANITY;
    }

    struct spawn_data spawn_data = { container, container_start_fn };

    pid_t child_pid = spawn(
            (int (*)(void *))spawn_main,
            CLONE_NEWCGROUP | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID,
            &spawn_data
    );

    if(child_pid < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    container->init_pid = child_pid;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_spawn_kill(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->init_pid <= 0) {
        return CONTAINER_ERROR_SANITY;
    }

    if(kill(container->init_pid, SIGKILL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    container->init_pid = 0;
    return CONTAINER_ERROR_OKAY;
}