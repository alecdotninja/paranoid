#include <stdlib.h>
#include <stdio.h>

#include "container/container.h"

int main(int argc, char *argv[]) {
    if(argc < 4) {
        fprintf(stdout, "Usage: %s HOSTNAME ROOT_FS_PATH INIT_PATH [INIT_ARGS...]\n", argv[0]);

        exit(EXIT_FAILURE);
    }

    container_t container;
    container.hostname = argv[1];
    container.root_path = argv[2];
    container.init_argc = argc - 2;
    container.init_argv = &argv[3];

    container_start(&container);
    container_wait(&container);

    return container.exit_code;
}
