#include <stdlib.h>
#include <stdio.h>
#include <argp.h>

#include "container/container.h"
#include "container/networking.h"

struct arguments {
    bool networking;
    char *hostname;
    char *root;
    char *init_argv[1024];
};

const char *argp_program_version = "paranoid-0.1.1";
const char *argp_program_bug_address = "Github (https://github.com/anarchocurious/paranoid/issues)";
const char *args_doc = "--root=ROOT_PATH -- INIT [INIT_ARGS...]";
const char *doc =   "Paranoid is a fully rootless containeriztion tool. It allows unprivileged users "
                    "on a system to create light-weight containers in which they can act as root.";

/* The options we understand. */
static const struct argp_option options[] = {
        { "disable-networking",  'N',    0,              0,  "Disable networking within the container" },
        { "hostname",            'h',    "HOSTNAME",     0,  "Set the hostname within the container" },
        { "root",                'r',    "ROOT_PATH",    0,  "Set the root within the container" },
        { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch(key) {
        case 'N':
            arguments->networking = false;
            break;
        case 'h':
            arguments->hostname = arg;
            break;
        case 'r':
            arguments->root = arg;
            break;
        case ARGP_KEY_ARG:
            if(state->arg_num >= 1024) {
                argp_usage(state);
            }

            arguments->init_argv[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if(arguments->root == NULL) {
                argp_usage(state);
            }

            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int main (int argc, char **argv) {
    struct arguments arguments = { 0 };
    struct argp argp = { options, parse_opt, args_doc, doc };

    arguments.networking = true;
    arguments.hostname = "paranoid";
    arguments.root = NULL;
    arguments.init_argv[0] = "/bin/bash";
    arguments.init_argv[1] = "-c";
    arguments.init_argv[2] = "/sbin/login -f root";

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    container_t container;
    container_init(&container, arguments.root, arguments.init_argv);
    container_networking_set_enabled(&container, arguments.networking);
    container_networking_set_hostname(&container, arguments.hostname);

    container_error_t error;

    if((error = container_start(&container)) != CONTAINER_ERROR_OKAY) {
        fprintf(stderr, "Failed to start container: %s\n", container_explain_error(error));
    }

    if((error = container_wait(&container)) != CONTAINER_ERROR_OKAY) {
        fprintf(stderr, "Failed to wait for container: %s\n", container_explain_error(error));
    }

    return container.init_exit_code;
}
