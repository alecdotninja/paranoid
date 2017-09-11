#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <container/signaling.h>
#include <grp.h>
#include <pwd.h>

#include "container/userns.h"

static int set_uid_map(pid_t pid_outside, uid_t start_uid_inside, uid_t start_uid_outside, size_t extent_size) {
    if(start_uid_inside == start_uid_outside) {
        return 0;
    }

    char path[256] = { 0 };

    if(snprintf(path, sizeof(path), "/proc/%u/uid_map", pid_outside) > sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_WRONLY);

    if(fd < 0) {
        return -2;
    }

    if(dprintf(fd, "%u %u %zu\n", start_uid_inside, start_uid_outside, extent_size) < 0) {
        return -3;
    }

    if(close(fd) < 0) {
        return -4;
    }

    return 0;
}

static int set_gid_map(pid_t pid_outside, gid_t start_gid_inside, gid_t start_gid_outside, size_t extent_size) {
    if(start_gid_inside == start_gid_outside) {
        return 0;
    }

    char path[256] = { 0 };

    if(snprintf(path, sizeof(path), "/proc/%u/gid_map", pid_outside) > sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_WRONLY);

    if(fd < 0) {
        return -2;
    }

    if(dprintf(fd, "%u %u %zu\n", start_gid_inside, start_gid_outside, extent_size) < 0) {
        return -3;
    }

    if(close(fd) < 0) {
        return -4;
    }

    return 0;
}

static int disable_setgroups(pid_t pid_outside) {
    char path[256] = { 0 };

    if(snprintf(path, sizeof(path), "/proc/%u/setgroups", pid_outside) > sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_RDWR);

    if(fd < 0) {
        return -2;
    }

    if(dprintf(fd, "deny") < 0) {
        return -3;
    }

    if(close(fd) < 0) {
        return -4;
    }
}

static int map_effective_id_as_root_for_process(pid_t pid) {
    uid_t uid = geteuid();
    gid_t gid = geteuid();

    disable_setgroups(pid);

    if(set_uid_map(pid, 0, uid, 1) < 0) {
        return -1;
    }

    if(set_gid_map(pid, 0, gid, 1) < 0) {
        return -1;
    }

    return 0;
}

static int scan_shadow_subid_config(const char *filename, const char *target_loginname, unsigned int *target_subid_start, size_t *target_subid_count) {
    FILE *subid_config;
    if((subid_config = fopen(filename, "r")) == NULL) {
        return -1;
    }

    int found = 0;

    char *buffer = NULL;
    size_t buffer_size = 0;

    char loginname[32] = { 0 };
    unsigned int subid_start = 0;
    size_t subid_count = 0;

    while(getline(&buffer, &buffer_size, subid_config) > 0) {
        if(sscanf(buffer, "%32[^:]:%u:%lu", loginname, &subid_start, &subid_count) == 3) {
            if(strcmp(loginname, target_loginname) == 0) {
                found = 1;
                break;
            }
        }
    }

    if(buffer != NULL) {
        free(buffer);
    }

    fclose(subid_config);

    if(found == 0) {
        return -1;
    }

    *target_subid_start = subid_start;
    *target_subid_count = subid_count;

    return 0;
}

static int map_effective_id_as_root_and_subids_for_process(pid_t pid) {
    gid_t gid = geteuid();
    uid_t uid = geteuid();

    const struct passwd *passwd;
    const char *loginname;
    if((passwd = getpwuid(uid)) == NULL || (loginname = passwd->pw_name) == NULL) {
        return -1;
    }

    uid_t subuid_start;
    size_t subuid_count;
    if(scan_shadow_subid_config("/etc/subuid", loginname, &subuid_start, &subuid_count) < 0) {
        return -2;
    }

    gid_t subgid_start;
    size_t subgid_count;
    if(scan_shadow_subid_config("/etc/subgid", loginname, &subgid_start, &subgid_count) < 0) {
        return -3;
    }

    char cmdline[256];
    snprintf(cmdline, sizeof(cmdline), "newuidmap %u 0 %u 1 1 %u %lu", pid, uid, subuid_start, subuid_count);
    if(system(cmdline) != EXIT_SUCCESS) {
        return -4;
    }

    snprintf(cmdline, sizeof(cmdline), "newgidmap %u 0 %u 1 1 %u %lu", pid, gid, subgid_start, subgid_count);
    if(system(cmdline) != EXIT_SUCCESS) {
        return -5;
    }

    return 0;
}

container_error_t container_user_namespace_initialize_parent(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(map_effective_id_as_root_and_subids_for_process(container->init_pid) < 0) {
        if(map_effective_id_as_root_for_process(container->init_pid) < 0) { // fallback to just root in container
            return CONTAINER_ERROR_USER;
        }
    }

    return container_signaling_sync(container);
}

container_error_t container_user_namespace_initialize_child(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    container_error_t container_error;
    if((container_error = container_signaling_sync(container)) != CONTAINER_ERROR_OKAY) {
        return container_error;
    }

    if(setuid(0) < 0) {
        return CONTAINER_ERROR_USER;
    }

    if(setgid(0) < 0) {
        return CONTAINER_ERROR_USER;
    }

    if(setgroups(0, NULL) < 0) {
        // if the user does not have a shadow with uid maps,
        // we may have set /proc/self/setgroups so that this will fail
        if(errno != EPERM) {
            return CONTAINER_ERROR_USER;
        }
    }

    return CONTAINER_ERROR_OKAY;
}