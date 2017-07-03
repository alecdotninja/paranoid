#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "container/container.h"
#include "container/fs.h"
#include "container/init.h"
#include "container/networking.h"
#include "container/signaling.h"
#include "container/spawn.h"
#include "container/tty.h"
#include "container/unsafe.h"
#include "container/userns.h"

int child_main(container_t *container) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    container_finalize_signaling_socket_child(container);

    if(receive_message(container->child_signaling_fd) < 0) {
        exit(EXIT_FAILURE);
    }

    setuid(0);
    setgid(0);
    setgroups(0, NULL);

    container_initialize_network_namespace(container);
    container_initialize_fs_namespace(container);

    drop_unsafe_capabilities();
    disable_unsafe_syscalls();

    container_child_setup_tty(container);

    container_exec_init(container);

    return EXIT_FAILURE;
}

void container_start(container_t *container) {
    if(geteuid() == 0 || getegid() == 0) {
        fprintf(stderr, "[!] Warning! paraniod is not designed to be run as root.\n");
    }

    container_initialize_signaling_socket(container);
    container_spawn_child(container, child_main);
    container_finalize_signaling_socket_parent(container);
    container_initialize_user_namespace(container);

    send_message(container->parent_signaling_fd, 0);

    container_spawn_network_relay(container);
    container_spawn_tty_relay(container);
}

void container_wait(container_t *container) {
    int child_status;

    if(waitpid(container->child_pid, &child_status, 0) < 0) {
        fprintf(stderr, "[!] Cannot wait for child process with pid %i. Perhaps it died too soon.\n", container->child_pid);
        exit(EXIT_FAILURE);
    }

    if(!WIFEXITED(child_status)) {
        fprintf(stderr, "[!] Child process with pid %i terminated abnormally. Perhaps it was killed or segfault'd.\n", container->child_pid);
        exit(EXIT_FAILURE);
    }

    container->exit_code = WEXITSTATUS(child_status);
}
