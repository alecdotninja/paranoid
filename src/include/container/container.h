#ifndef PARANOID_CONTAINER_H
#define PARANOID_CONTAINER_H

#include <network_relay/network_relay.h>
#include <plumbing/fd_relay.h>

typedef enum {
    CONTAINER_STATE_STOPPED         = 0,
    CONTAINER_STATE_STARTING        = 1,
    CONTAINER_STATE_STARTED         = 2,
    CONTAINER_STATE_STOPPING        = 3,
} container_state_t;

typedef enum {
    /* everything is fine */
    CONTAINER_ERROR_OKAY            = 0,

    /* a syscall failed -- check errno */
    CONTAINER_ERROR_SYSTEM          = -1,

    /* an internal sanity check failed */
    CONTAINER_ERROR_SANITY          = -2,

    CONTAINER_ERROR_ARG             = -3,

    /* refused to run as root */
    CONTAINER_ERROR_ROOT            = -4,

    /* failed to setup the user namespace */
    CONTAINER_ERROR_USER            = -5,

    /* failed to set the hostname of container */
    CONTAINER_ERROR_NET_HOSTNAME    = -6,

    /* failed to create TAP device in network namespace */
    CONTAINER_ERROR_NET_TAP         = -7,

    /* failed to configure devices in the network namespace */
    CONTAINER_ERROR_NET_IFCONFIG    = -8,

    /* failed to start the network relay */
    CONTAINER_ERROR_NET_RELAY       = -9,

    /* failed to create the tty */
    CONTAINER_ERROR_TTY             = -10,
} container_error_t;

typedef struct container {
    container_state_t state;

    int parent_signaling_fd;
    int child_signaling_fd;

    const char *hostname;
    network_relay_t *network_relay;

    const char *root_path;

    fd_relay_t *stdin_relay;
    fd_relay_t *stdout_relay;

    pid_t init_pid;
    int init_argc;
    char **init_argv;
    int init_exit_code;
} container_t;

container_error_t container_init(container_t *container);
container_error_t container_start(container_t *container);
container_error_t container_wait(container_t *container);


#endif //PARANOID_CONTAINER_H