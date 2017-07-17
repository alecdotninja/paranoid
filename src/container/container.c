#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "container/container.h"
#include "container/fsns.h"
#include "container/init.h"
#include "container/networking.h"
#include "container/signaling.h"
#include "container/spawn.h"
#include "container/tty.h"
#include "container/unsafe.h"
#include "container/userns.h"

const char *container_explain_error(container_error_t error) {
    switch(error) {
        case CONTAINER_ERROR_OKAY:
            return "The operation completed successfully";
        case CONTAINER_ERROR_SYSTEM:
            return strerror(errno);
        case CONTAINER_ERROR_ARG:
            return "Incorrect argument";
        case CONTAINER_ERROR_ROOT:
            return "Refused to run as root";
        case CONTAINER_ERROR_USER:
            return "Failed to create user namespace";
        case CONTAINER_ERROR_NET_HOSTNAME:
            return "Failed to set hostname";
        case CONTAINER_ERROR_NET_TAP:
            return "Failed to create TAP device in network namespace";
        case CONTAINER_ERROR_NET_IFCONFIG:
            return "Failed to configure TAP device in network namespace";
        case CONTAINER_ERROR_NET_RELAY:
            return "Failed to start network relay";
        case CONTAINER_ERROR_TTY:
            return "Failed to create TTY";
        default:
            return "An unknown error occurred";
    }
}

static container_error_t container_start_child(container_t *container) {
    container_error_t error;

    if((error = container_signaling_initialize_child(container)) != CONTAINER_ERROR_OKAY) {
       return error;
    }

    if((error = container_user_namespace_initialize_child(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_networking_initialize_child(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_initialize(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    // TODO: These should probably have some kind of error checking
    drop_unsafe_capabilities();
    disable_unsafe_syscalls();

    if((error = container_tty_initialize_child(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_init_exec(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t container_start_parent(container_t *container) {
    container_error_t error;

    if((error = container_signaling_initialize_parent(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_user_namespace_initialize_parent(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_networking_initialize_parent(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_tty_initialize_parent(container)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_init(container_t *container, const char *root_path, char **init_argv) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    container->state = CONTAINER_STATE_STOPPED;
    container->parent_signaling_fd = -1;
    container->child_signaling_fd = -1;

    container->networking_enabled = false;
    container->hostname = NULL;
    container->network_relay = NULL;
    container->port_mappings = NULL;
    container->port_mapping_count = 0;

    container->root_path = root_path;
    container->stdin_relay = NULL;
    container->stdout_relay = NULL;

    container->init_pid = 0;
    container->init_argv = init_argv;
    container->init_exit_code = 0;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_start(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_SANITY;
    }

    if(geteuid() == 0 || getegid() == 0) {
        return CONTAINER_ERROR_ROOT;
    }

    container->state = CONTAINER_STATE_STARTING;

    container_error_t error;

    if((error = container_signaling_initialize_pre_spawn(container)) != CONTAINER_ERROR_OKAY) {
        goto failed_initialize_signaling_socket;
    }

    if((error = container_spawn(container, container_start_child)) != CONTAINER_ERROR_OKAY) {
        goto failed_spawn_child;
    }

    if((error = container_start_parent(container)) != CONTAINER_ERROR_OKAY) {
        goto failed_start_parent;
    }

    return CONTAINER_ERROR_OKAY;

failed_start_parent:
    container_spawn_kill(container);

failed_spawn_child:
    container_signaling_finalize(container);

failed_initialize_signaling_socket:
    container->state = CONTAINER_STATE_STOPPED;

    return error;
}

container_error_t container_wait(container_t *container) {
    int status;

    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state == CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_OKAY;
    }

    if(container->init_pid < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    do {
        if(waitpid(container->init_pid, &status, 0) < 0) {
            return CONTAINER_ERROR_SYSTEM;
        }
    }while(!WIFEXITED(status) && !WIFSIGNALED(status));

    container->init_exit_code = WEXITSTATUS(status);

    return CONTAINER_ERROR_OKAY;
}
