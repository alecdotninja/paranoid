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
    port_mapping_t port_mappings[1024];
    size_t port_mapping_count;
};

const char *argp_program_version = "paranoid-0.1.1";
const char *argp_program_bug_address = "Github (https://github.com/anarchocurious/paranoid/issues)";
const char *args_doc = "--root=ROOT_PATH -- INIT [INIT_ARGS...]";
const char *doc =   "Paranoid is a fully rootless containeriztion tool. It allows unprivileged users "
                    "on a system to create light-weight containers in which they can act as root.";

/* The options we understand. */
static const struct argp_option options[] = {
        { "disable-networking",  'N',    0,                     0,  "Disable networking within the container" },
        { "expose",              'e',    "PORT:PORT:PROTOCOL",  0,  "Expose PORT inside container as PORT on host via PROTOCOL (requires networking)" },
        { "hostname",            'h',    "HOSTNAME",            0,  "Set the hostname within the container" },
        { "root",                'r',    "ROOT_PATH",           0,  "Set the root within the container" },
        { 0 }
};

static error_t parse_expose_opt(char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    port_mapping_t *port_mapping;

    port_mapping = &arguments->port_mappings[arguments->port_mapping_count++];
    IP4_ADDR(&port_mapping->remote_address, 10,0,15,2);

    char protocol[16] = { 0 };

    switch(sscanf(arg, "%hu:%hu:%16s", &port_mapping->local_port, &port_mapping->remote_port, protocol)) {
        case 1:
            port_mapping->protocol = PORT_MAPPING_PROTOCOL_TCP;
            port_mapping->remote_port = port_mapping->local_port;
            break;
        case 2:
            port_mapping->protocol = PORT_MAPPING_PROTOCOL_TCP;
            break;
        case 3:
            if(strcasecmp(protocol, "TCP") == 0) {
                port_mapping->protocol = PORT_MAPPING_PROTOCOL_TCP;
                break;
            }

            if(strcasecmp(protocol, "UDP") == 0) {
                port_mapping->protocol = PORT_MAPPING_PROTOCOL_UDP;
                break;
            }
        default:
            argp_usage(state);
            break;
    }

    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch(key) {
        case 'N':
            arguments->networking = false;
            break;
        case 'e':
            return parse_expose_opt(arg, state);
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
            if(arguments->root == NULL || state->arg_num < 1) {
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
    arguments.init_argv[0] = NULL;
    arguments.port_mapping_count = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    container_t container;
    container_init(&container, arguments.root, arguments.init_argv);
    container_networking_set_enabled(&container, arguments.networking);
    container_networking_set_hostname(&container, arguments.hostname);
    container_networking_set_port_mappings(&container, arguments.port_mapping_count, arguments.port_mappings);

    container_error_t error;

    if((error = container_start(&container)) != CONTAINER_ERROR_OKAY) {
        fprintf(stderr, "Failed to start container: %s\n", container_explain_error(error));
        exit(EXIT_FAILURE);
    }

    if((error = container_wait(&container)) != CONTAINER_ERROR_OKAY) {
        fprintf(stderr, "Failed to wait for container: %s\n", container_explain_error(error));
        exit(EXIT_FAILURE);
    }

    return container.init_exit_code;
}
