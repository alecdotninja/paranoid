#define _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <libcgroup.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <zconf.h>
#include <container/fd_relay.h>

#include "container/fs.h"

static void link_dev(const char * source_path, const char * dest_path, mode_t mode) {
    mknod(dest_path, mode, S_IFCHR);

    if(mount(source_path, dest_path, NULL, MS_BIND, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount %s inside container.\n", dest_path);
        exit(EXIT_FAILURE);
    }
}

static void build_dev() {
    // http://www.linuxfromscratch.org/lfs/view/6.1/chapter06/devices.html
    mkdir("./dev", S_IRWXU);

    if(mount("tmpfs", "./dev", "tmpfs", MS_NOSUID, "") < 0) {
        fprintf(stderr, "[!] Cannot mount dev inside container.\n");
        exit(EXIT_FAILURE);
    }

    mkdir("./dev/pts", 755);

    if(mount("devpts", "./dev/pts", "devpts", MS_MGC_VAL, "newinstance") < 0) {
        fprintf(stderr, "[!] Cannot mount pts inside container.\n");
        exit(EXIT_FAILURE);
    }

    mkdir("./dev/net", 755);

    if(mount("/dev/net", "./dev/net", NULL, MS_BIND | MS_REC, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount net inside container.\n");
        exit(EXIT_FAILURE);
    }

    mkdir("./dev/shm", 755);

    if(mount("tmpfs", "./dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.\n");
        exit(EXIT_FAILURE);
    }

    link_dev("/dev/null", "./dev/null", 666);
    link_dev("/dev/zero", "./dev/zero", 666);
    link_dev("/dev/random", "./dev/random", 444);
    link_dev("/dev/urandom", "./dev/urandom", 444);
    link_dev("/dev/full", "./dev/full", 622);
    link_dev("/dev/tty", "./dev/tty", 755);
    link_dev("./dev/pts/ptmx", "./dev/ptmx", 666);

    symlink("/proc/self/fd", "./dev/fd");
    symlink("/proc/kcore", "./dev/core");
    symlink("/proc/self/fd/0", "./dev/stdin");
    symlink("/proc/self/fd/1", "./dev/stdout");
    symlink("/proc/self/fd/2", "./dev/stderr");
}

static void mount_cgroup_subsystem(const char * subsystem) {
    char path[2048];
    snprintf(path, sizeof(path), "./sys/fs/cgroup/%s", subsystem);

    mkdir(path, S_IRWXU);

    if(mount("cgroup", path, "cgroup", MS_MGC_VAL | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, subsystem) < 0) {
        fprintf(stderr, "[!] Failed to mount %s cgroup subsystem at %s.\n", subsystem, path);
    }
}

static void mount_cgroup_subsystems() {
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
            mount_cgroup_subsystem(subsystem);
        }
    }
}

static void build_sys() {
    mkdir("./sys", S_IRWXU);

    if(mount("sysfs", "./sys", "sysfs", MS_MGC_VAL, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount sys inside container.\n");
        exit(EXIT_FAILURE);
    }

    if(mount("tmpfs", "./sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "mode=755") < 0) {
        fprintf(stderr, "[!] Cannot mount cgroup root inside container.\n");
        exit(EXIT_FAILURE);
    }

    mount_cgroup_subsystems();

    if(mount("tmpfs", "./sys/fs/cgroup", "tmpfs", MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        fprintf(stderr, "[!] Cannot remount cgroup root as readonly.\n");
        exit(EXIT_FAILURE);
    }
}

static void build_proc() {
    mkdir("./proc", S_IRWXU);

    if(mount("proc", "./proc", "proc", MS_MGC_VAL, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount proc inside container.\n");
        exit(EXIT_FAILURE);
    }
}

static void build_tmp_and_run() {
    mkdir("./tmp", S_IRWXU);

    if(mount("tmpfs", "./tmp", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.\n");
        exit(EXIT_FAILURE);
    }

    mkdir("./run", S_IRWXU);

    if(mount("tmpfs", "./run", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.\n");
        exit(EXIT_FAILURE);
    }

    mkdir("./run/lock", S_IRWXU);

    if(mount("tmpfs", "./run/lock", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.\n");
        exit(EXIT_FAILURE);
    }
}

void container_initialize_fs_namespace(container_t *container) {
    if(unshare(CLONE_FS) < 0) {
        fprintf(stderr, "[!] Cannot enter a file system namespace. Perhaps your kernel does not support it.\n");
        exit(EXIT_FAILURE);
    }

    if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        fprintf(stderr, "[!] Cannot create a private mount tree. Perhaps your kernel does not support it.\n");
        exit(EXIT_FAILURE);
    }

    if(mount(container->root_path, container->root_path, NULL, MS_BIND, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount root_path inside container.\n");
        exit(EXIT_FAILURE);
    }

    if(chdir(container->root_path) < 0) {
        fprintf(stderr, "[!] Cannot move to root inside container.\n");
        exit(EXIT_FAILURE);
    }

    build_proc();
    build_sys();
    build_dev();
    build_tmp_and_run();

//    copy_file("/etc/resolv.conf", "./etc/resolv.conf");

    char old_root_path[] = "./tmp/old-root.XXXXXX";
    if(mkdtemp(old_root_path) == NULL) {
        fprintf(stderr, "[!] Could not create mount point for old root.\n");
        exit(EXIT_FAILURE);
    }

    if(pivot_root(".", old_root_path) < 0) {
        fprintf(stderr, "[!] Could not pivot to new root.\n");
        exit(EXIT_FAILURE);
    }

    if(umount2(old_root_path, MNT_DETACH) < 0) {
        fprintf(stderr, "[!] Could not detach from old root.\n");
        exit(EXIT_FAILURE);
    }

    if(rmdir(old_root_path) < 0) {
        fprintf(stderr, "[!] Could remove old root mount point.\n");
        exit(EXIT_FAILURE);
    }

    if(chdir("/") < 0) {
        fprintf(stderr, "[!] Could not move to new root.\n");
        exit(EXIT_FAILURE);
    }
}