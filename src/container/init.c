#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "container/init.h"

static ssize_t mkenviron(char *buffer, size_t buffer_size, const char *key, const char *default_value) {
    const char *value = secure_getenv(key);

    if(value == NULL) {
        value = default_value;
    }

    ssize_t written = snprintf(buffer, buffer_size, "%s=%s", key, value);

    if(written > 0 && written <= buffer_size) {
        return 0;
    }else{
        return -1;
    }
}

container_error_t container_init_exec(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    char term_environ[32];
    if(mkenviron(term_environ, sizeof(term_environ), "TERM", "linux") < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    char lang_environ[32];
    if(mkenviron(lang_environ, sizeof(lang_environ), "LANG", "en_US.UTF-8") < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    char *envp[] = { term_environ, lang_environ, "container=paranoid", NULL };

    if(execvpe(container->init_argv[0], container->init_argv, envp) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_SANITY;
}

container_error_t container_set_init(container_t *container, int argc, char ** argv) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_ARG;
    }

    container->init_argc = argc;
    container->init_argv = argv;

    return CONTAINER_ERROR_OKAY;
}