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

void container_exec_init(container_t *container) {
    char term_environ[32];
    if(mkenviron(term_environ, sizeof(term_environ), "TERM", "linux") < 0) {
        fprintf(stderr, "[!] Failed to setup env.\n");
        exit(EXIT_FAILURE);
    }

    char lang_environ[32];
    if(mkenviron(lang_environ, sizeof(lang_environ), "LANG", "en_US.UTF-8") < 0) {
        fprintf(stderr, "[!] Failed to setup env.\n");
        exit(EXIT_FAILURE);
    }

    char *envp[] = { term_environ, lang_environ, "container=paranoid", NULL };

    if(execvpe(container->init_argv[0], container->init_argv, envp) < 0) {
        fprintf(stderr, "[!] Failed to exec init (%s).\n", container->init_argv[0]);
        exit(EXIT_FAILURE);
    }
}
