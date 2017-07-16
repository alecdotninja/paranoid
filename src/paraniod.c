#include <stdlib.h>
#include <stdio.h>
#include <container/networking.h>
#include <container/fsns.h>
#include <container/init.h>
#include <errno.h>

#include "container/container.h"

int main(int argc, char *argv[]) {
    if(argc < 4) {
        fprintf(stdout, "Usage: %s HOSTNAME ROOT_FS_PATH INIT_PATH [INIT_ARGS...]\n", argv[0]);

        exit(EXIT_FAILURE);
    }

    container_t container;
    container_init(&container);

    container_set_hostname(&container, argv[1]);
    container_set_root_path(&container, argv[2]);
    container_set_init(&container, argc - 2, &argv[3]);

    container_error_t error;
    if((error = container_start(&container)) != CONTAINER_ERROR_OKAY) {
        fprintf(stderr, "[!] Failed to start container! (%i, %i)\n", error, errno);
    }

    container_wait(&container);

    return container.init_exit_code;
}
