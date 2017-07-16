#define _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <libcgroup.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <zconf.h>
#include "syscall.h"

#include "container/fsns.h"

#define pivot_root(new_root, put_old_root) syscall(SYS_pivot_root, new_root, put_old_root)

container_error_t container_fs_namespace_bind_mount(const char *source_path, const char *destination_path, mode_t mode) {
    if(mknod(destination_path, mode, S_IFCHR) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(mount(source_path, destination_path, NULL, MS_BIND, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t build_dev() {
    container_error_t error;

    // http://www.linuxfromscratch.org/lfs/view/6.1/chapter06/devices.html
    mkdir("./dev", S_IRWXU);

    if(mount("tmpfs", "./dev", "tmpfs", MS_NOSUID, "") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    mkdir("./dev/pts", 755);

    if(mount("devpts", "./dev/pts", "devpts", MS_MGC_VAL, "newinstance") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    mkdir("./dev/net", 755);

    if(mount("/dev/net", "./dev/net", NULL, MS_BIND | MS_REC, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    mkdir("./dev/shm", 755);

    if(mount("tmpfs", "./dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if((error = container_fs_namespace_bind_mount("/dev/null", "./dev/null", 666)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("/dev/zero", "./dev/zero", 666)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("/dev/random", "./dev/random", 444)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("/dev/urandom", "./dev/urandom", 444)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("/dev/full", "./dev/full", 622)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("/dev/tty", "./dev/tty", 755)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = container_fs_namespace_bind_mount("./dev/pts/ptmx", "./dev/ptmx", 666)) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if(symlink("/proc/self/fd", "./dev/fd") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(symlink("/proc/kcore", "./dev/core") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(symlink("/proc/self/fd/0", "./dev/stdin") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(symlink("/proc/self/fd/1", "./dev/stdout") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(symlink("/proc/self/fd/2", "./dev/stderr") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t mount_cgroup_subsystem(const char * subsystem) {
    char path[2048];
    snprintf(path, sizeof(path), "./sys/fs/cgroup/%s", subsystem);

    mkdir(path, S_IRWXU);

    if(mount("cgroup", path, "cgroup", MS_MGC_VAL | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, subsystem) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t mount_cgroup_subsystems() {
    container_error_t error;
    void *handle;
    struct controller_data data;

    int status = cgroup_get_all_controller_begin(&handle, &data);

    char subsystems[16][1024] = { 0 };

    while (status != ECGEOF) {
        if(data.hierarchy >= 0 && data.hierarchy < 16) {
            char *subsystem = subsystems[data.hierarchy];

            if(strlen(subsystem) > 0) {
                strncat(subsystem, ",", 1024 - strlen(subsystem));
            }

            strncat(subsystem, data.name, 1024 - strlen(subsystem));
        }

        status = cgroup_get_all_controller_next(&handle, &data);

        if(status && status != ECGEOF) {
            break;
        }
    }

    cgroup_get_all_controller_end(&handle);

    for(size_t hierarchy = 0; hierarchy < 16; hierarchy++) {
        char *subsystem = subsystems[hierarchy];

        if (strlen(subsystem) > 0) {
            if((error = mount_cgroup_subsystem(subsystem)) != CONTAINER_ERROR_OKAY) {
                return error;
            }
        }
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t build_sys() {
    container_error_t error;

    mkdir("./sys", S_IRWXU);

    if(mount("sysfs", "./sys", "sysfs", MS_MGC_VAL, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(mount("tmpfs", "./sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "mode=755") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if((error = mount_cgroup_subsystems()) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if(mount("tmpfs", "./sys/fs/cgroup", "tmpfs", MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t build_proc() {
    mkdir("./proc", S_IRWXU);

    if(mount("proc", "./proc", "proc", MS_MGC_VAL, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

static container_error_t build_tmp_and_run() {
    mkdir("./tmp", S_IRWXU);

    if(mount("tmpfs", "./tmp", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    mkdir("./run", S_IRWXU);

    if(mount("tmpfs", "./run", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    mkdir("./run/lock", S_IRWXU);

    if(mount("tmpfs", "./run/lock", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_fs_namespace_initialize(container_t *container) {
    container_error_t error;

    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->root_path == NULL) {
        return CONTAINER_ERROR_ARG;
    }

    if(unshare(CLONE_FS) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(mount(container->root_path, container->root_path, NULL, MS_BIND, NULL) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(chdir(container->root_path) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if((error = build_proc()) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = build_sys()) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = build_dev()) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    if((error = build_tmp_and_run()) != CONTAINER_ERROR_OKAY) {
        return error;
    }

    char old_root_path[] = "./tmp/old-root.XXXXXX";
    if(mkdtemp(old_root_path) == NULL) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(pivot_root(".", old_root_path) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(umount2(old_root_path, MNT_DETACH) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(rmdir(old_root_path) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(chdir("/") < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_set_root_path(container_t *container, const char *root_path) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->state != CONTAINER_STATE_STOPPED) {
        return CONTAINER_ERROR_ARG;
    }

    if(root_path == NULL) {
        return CONTAINER_ERROR_ARG;
    }

    container->root_path = root_path;

    return CONTAINER_ERROR_OKAY;
}