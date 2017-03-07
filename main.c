#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <stropts.h>
#include <pty.h>
#include <utmp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define pivot_root(new_root, put_old_root) syscall(SYS_pivot_root, new_root, put_old_root)

#define CHILD_STACK_SIZE (size_t)(1024 * 1024)
#define CHILD_CLONE_FLAGS (CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID)

char child_stack[CHILD_STACK_SIZE] = { 0 };
#define CHILD_STACK_TOP (void *)(child_stack + CHILD_STACK_SIZE)

typedef struct __container {
    pid_t child_pid;
    int parent_signaling_fd;
    int child_signaling_fd;

    const char *hostname;
    const char *root_path;
    int init_argc;
    char **init_argv;

    int exit_code;
} container_t;

#define FD_TRANSIT_CHECK (1337)

ssize_t send_fd(int socket_fd, int fd) {
    struct msghdr msgh;
    struct iovec iov;
    int data = FD_TRANSIT_CHECK;

    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmhp;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    iov.iov_base = &data;
    iov.iov_len = sizeof(data);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    cmhp = CMSG_FIRSTHDR(&msgh);
    cmhp->cmsg_len = CMSG_LEN(sizeof(int));
    cmhp->cmsg_level = SOL_SOCKET;
    cmhp->cmsg_type = SCM_RIGHTS;
    *((int *) CMSG_DATA(cmhp)) = fd;

    return sendmsg(socket_fd, &msgh, 0);
}

int recv_fd(int socket_fd) {
    struct msghdr msgh;
    struct iovec iov;
    int data;

    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmhp;

    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_RIGHTS;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(data);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    if(recvmsg(socket_fd, &msgh, 0) < 0) {
        return -1;
    }

    cmhp = CMSG_FIRSTHDR(&msgh);
    if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(int)))
        return -2;
    if (cmhp->cmsg_level != SOL_SOCKET)
        return -3;
    if (cmhp->cmsg_type != SCM_RIGHTS)
        return -4;

    int fd = *((int *) CMSG_DATA(cmhp));

    if(data == FD_TRANSIT_CHECK) {
        return fd;
    }else{
        return -5;
    }
}

int copy_file(const char * source_file_path, const char * destination_file_path) {
    int source_file_fd = open(source_file_path, O_RDONLY);

    if(source_file_fd < 0) {
        return -1;
    }

    int destination_file_fd = open(destination_file_path, O_CREAT | O_WRONLY);

    if(destination_file_fd < 0) {
        return -2;
    }

    char buffer[BUFSIZ];
    ssize_t size;

    while((size = read(source_file_fd, buffer, sizeof(buffer))) > 0) {
        if(write(destination_file_fd, buffer, (size_t)size) < size) {
            return -3;
        }
    }

    close(source_file_fd);
    close(destination_file_fd);

    return 0;
}

pid_t spawn_relay(int in_fd, int out_fd) {
    pid_t relay_pid;
    if((relay_pid = fork()) < 0) {
        fprintf(stderr, "[!] Failed to create relay (%i -> %i).\n", in_fd, out_fd);
    }

    if(relay_pid == 0) {
        if(prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            _exit(EXIT_FAILURE);
        }

        char buffer[128];
        ssize_t remaing, written;

        while(1) {
            if((remaing = read(in_fd, &buffer, sizeof(buffer))) < 0) {
                break;
            }

            if(remaing == 0) {
                break;
            }

            while(remaing > 0) {
                if((written = write(out_fd, &buffer, (size_t)remaing)) < 0) {
                    break;
                }

                remaing -= written;
            }
        }

        _exit(EXIT_FAILURE);
    }

    return relay_pid;
}

void container_initialize_fs_namespace(container_t *container) {
    if(unshare(CLONE_FS) < 0) {
        fprintf(stderr, "[!] Cannot enter a file system namespace. Perhaps your kernel does not support it.");
        exit(EXIT_FAILURE);
    }

    if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        fprintf(stderr, "[!] Cannot create a private mount tree. Perhaps your kernel does not support it.");
        exit(EXIT_FAILURE);
    }

    if(mount(container->root_path, container->root_path, NULL, MS_BIND, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount root_path inside container.");
        exit(EXIT_FAILURE);
    }

    if(chdir(container->root_path) < 0) {
        fprintf(stderr, "[!] Cannot move to root inside container.");
        exit(EXIT_FAILURE);
    }

    mkdir("./proc", S_IRWXU);
    mkdir("./sys", S_IRWXU);
    mkdir("./dev", S_IRWXU);
    mkdir("./tmp", S_IRWXU);
    mkdir("./run", S_IRWXU);
    mkdir("./ect", S_IRWXU);

    copy_file("/etc/resolv.conf", "./etc/resolv.conf");

    if(mount("proc", "./proc", "proc", MS_MGC_VAL, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount proc inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("/sys", "./sys", NULL, MS_BIND | MS_REC | MS_RDONLY, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount sys inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("/dev", "./dev", NULL, MS_BIND | MS_REC | MS_RDONLY, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount dev inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("devpts", "./dev/pts", "devpts", MS_MGC_VAL, "newinstance") < 0) {
        fprintf(stderr, "[!] Cannot mount pts inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("./dev/pts/ptmx", "./dev/ptmx", NULL, MS_BIND | MS_REC, NULL) < 0) {
        fprintf(stderr, "[!] Cannot mount ptmx inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("tmpfs", "./tmp", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.");
        exit(EXIT_FAILURE);
    }

    if(mount("tmpfs", "./run", "tmpfs", MS_NOSUID | MS_NODEV, "") < 0) {
        fprintf(stderr, "[!] Cannot mount tmp inside container.");
        exit(EXIT_FAILURE);
    }

    char old_root_path[] = "./tmp/old-root.XXXXXX";
    if(mkdtemp(old_root_path) == NULL) {
        fprintf(stderr, "[!] Could not create mount point for old root.");
        exit(EXIT_FAILURE);
    }

    if(pivot_root(".", old_root_path) < 0) {
        fprintf(stderr, "[!] Could not pivot to new root.");
        exit(EXIT_FAILURE);
    }

    if(umount2(old_root_path, MNT_DETACH) < 0) {
        fprintf(stderr, "[!] Could not detach from old root.");
        exit(EXIT_FAILURE);
    }

    if(rmdir(old_root_path) < 0) {
        fprintf(stderr, "[!] Could remove old root mount point.");
        exit(EXIT_FAILURE);
    }

    if(chdir("/") < 0) {
        fprintf(stderr, "[!] Could not move to new root.");
        exit(EXIT_FAILURE);
    }
}

const int UNSAFE_CAPABILITIES[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
};

void drop_unsafe_capabilities() {
    for(size_t index = 0; index < sizeof(UNSAFE_CAPABILITIES); index++) {
        prctl(PR_CAPBSET_DROP, UNSAFE_CAPABILITIES[index], 0, 0, 0);
    }

    cap_t capabilities = cap_get_proc();

    if(capabilities != NULL) {
        cap_set_flag(capabilities, CAP_INHERITABLE, sizeof(UNSAFE_CAPABILITIES), UNSAFE_CAPABILITIES, CAP_CLEAR);
        cap_set_proc(capabilities);
        cap_free(capabilities);
    }
}

int set_uid_map(pid_t pid_outside, uid_t start_uid_inside, uid_t start_uid_outside, size_t extent_size) {
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

int set_gid_map(pid_t pid_outside, gid_t start_gid_inside, gid_t start_gid_outside, size_t extent_size) {
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

int disable_setgroups(pid_t pid_outside) {
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

void container_initialize_signaling_socket(container_t *container) {
    int signaling_fds[2];

    if(socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, signaling_fds)) {
        fprintf(stderr, "[!] Cannot create signaling socket.\n");
        exit(EXIT_FAILURE);
    }

    container->parent_signaling_fd = signaling_fds[0];
    container->child_signaling_fd = signaling_fds[1];

    if(fcntl(container->parent_signaling_fd, F_SETFD, FD_CLOEXEC) < 0) {
        fprintf(stderr, "[!] Cannot fcntl parent signaling fd.\n");
        exit(EXIT_FAILURE);
    }

    if(fcntl(container->child_signaling_fd, F_SETFD, FD_CLOEXEC) < 0) {
        fprintf(stderr, "[!] Cannot fcntl child signaling fd.\n");
        exit(EXIT_FAILURE);
    }
}

void container_finalize_signaling_socket_parent(container_t *container) {
    if(close(container->child_signaling_fd) < 0) {
        fprintf(stderr, "[!] Cannot close child end of the signaling socket from the parent.\n");
        exit(EXIT_FAILURE);
    }

    container->child_signaling_fd = -1;
}

void container_finalize_signaling_socket_child(container_t *container) {
    if(close(container->parent_signaling_fd) < 0) {
        fprintf(stderr, "[!] Cannot close child end of the signaling socket from the parent.\n");
        exit(EXIT_FAILURE);
    }

    container->parent_signaling_fd = -1;
}

int receive_message(int signaling_fd) {
    int message;

    if(read(signaling_fd, &message, sizeof(message)) != sizeof(message)) {
        return -255;
    }

    return message;
}

void send_message(int signaling_fd, int message) {
    if(write(signaling_fd, &message, sizeof(message)) != sizeof(message)) {
        fprintf(stderr, "[!] Failed to send message %i\n", message);
        exit(EXIT_FAILURE);
    }
}

int open_tun() {
    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

    if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);

        return err;
    }

    return fd;
}

void container_initialize_network_namespace(container_t *container) {
    sethostname(container->hostname, strlen(container->hostname));

//    int tun_fd;
//    if((tun_fd = open_tun()) < 0) {
//        fprintf(stderr, "[!] Failed to create eth0\n");
//        exit(EXIT_FAILURE);
//    }
//
//    if(send_fd(container->child_signaling_fd, tun_fd) < 0) {
//        fprintf(stderr, "[!] Failed to send eth0 outside of the container\n");
//        exit(EXIT_FAILURE);
//    }
//
//    if(receive_message(container->child_signaling_fd) < 0) {
//        fprintf(stderr, "[!] Failed to wait for parent to take ownership of eth0\n");
//        exit(EXIT_FAILURE);
//    }
//
//    if(close(tun_fd) < 0) {
//        fprintf(stderr, "[!] Failed to abandon eth0\n");
//        exit(EXIT_FAILURE);
//    }
//
//    system("ip link set dev lo up");
//    system("ip link set dev eth0 up");
//    system("ip addr add 10.0.15.2 dev eth0");
//    system("ip route add 10.0.15.0/24 dev eth0");
//    system("ip route add default via 10.0.15.1");
}

void container_exec_init(container_t *container) {
    if(execvpe(container->init_argv[0], container->init_argv, NULL) < 0) {
        fprintf(stderr, "[!] Failed to exec init (%s).\n", container->init_argv[0]);
        exit(EXIT_FAILURE);
    }
}

void container_child_setup_tty(container_t *container) {
    int master_fd, slave_fd;

    if(openpty(&master_fd, &slave_fd, NULL, NULL, NULL) < 0) {
        fprintf(stderr, "[!] Failed to create pty.\n");
        exit(EXIT_FAILURE);
    }

    if(send_fd(container->child_signaling_fd, master_fd) < 0) {
        fprintf(stderr, "[!] Failed to send pty to parent.\n");
        exit(EXIT_FAILURE);
    }

    if(receive_message(container->child_signaling_fd) < 0) {
        fprintf(stderr, "[!] Parent did not accept tty.\n");
        exit(EXIT_FAILURE);
    }

    close(master_fd);

    setsid();

    if(ioctl(slave_fd, TIOCSCTTY, NULL) < 0) {
        fprintf(stderr, "[!] Failed set tty to leader.\n");
        exit(EXIT_FAILURE);
    }

    if(isatty(STDIN_FILENO)) {
        if(dup2(slave_fd, STDIN_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDIN.\n");
            exit(EXIT_FAILURE);
        }
    }

    if(isatty(STDOUT_FILENO)) {
        if(dup2(slave_fd, STDOUT_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDOUT.\n");
            exit(EXIT_FAILURE);
        }
    }

    if(isatty(STDERR_FILENO)) {
        if(dup2(slave_fd, STDERR_FILENO) < 0) {
            fprintf(stderr, "[!] Failed to tty to STDOUT.\n");
            exit(EXIT_FAILURE);
        }
    }

    close(slave_fd);
}

int child_main(void *data) {
    container_t *container = (container_t *)data;
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    container_finalize_signaling_socket_child(container);

    if(receive_message(container->child_signaling_fd) < 0) {
        exit(EXIT_FAILURE);
    }

    container_initialize_network_namespace(container);
    container_initialize_fs_namespace(container);

    drop_unsafe_capabilities();

    container_child_setup_tty(container);

    container_exec_init(container);

    return EXIT_FAILURE;
}

void container_initialize_user_namespace(container_t *container) {
    uid_t uid = geteuid();
    gid_t gid = geteuid();

    disable_setgroups(container->child_pid);

    if(set_uid_map(container->child_pid, 0, uid, 1) < 0) {
        fprintf(stderr, "[!] Failed to set uid map (%u %u %u) on child process %i.\n", 0, uid, 1, container->child_pid);
        exit(EXIT_FAILURE);
    }

    if(set_gid_map(container->child_pid, 0, gid, 1) < 0) {
        fprintf(stderr, "[!] Failed to set gid map (%u %u %u) on child process %i.\n", 0, gid, 1, container->child_pid);
        exit(EXIT_FAILURE);
    }
}

void container_spawn_child(container_t *container) {
    void *child_data = (void *)container;

    pid_t child_pid = clone(child_main, CHILD_STACK_TOP, CHILD_CLONE_FLAGS | SIGCHLD, child_data);

    if(child_pid < 0) {
        fprintf(stderr, "[!] Cannot spawn child process. Perhaps your kernel does not support namespaces?\n");
        exit(EXIT_FAILURE);
    }

    container->child_pid = child_pid;
}

//void container_spawn_network_relay(container_t *container) {
//    int tun_fd;
//    if((tun_fd = recv_fd(container->parent_signaling_fd)) < 0) {
//        fprintf(stderr, "[!] Cannot claim eth0.\n");
//        exit(EXIT_FAILURE);
//    }
//
//    spawn_relay(tun_fd, STDOUT_FILENO);
//
//    send_message(container->parent_signaling_fd, 0);
//}

void container_spawn_tty_relay(container_t *container) {
    int tty_fd;
    if((tty_fd = recv_fd(container->parent_signaling_fd)) < 0) {
        fprintf(stderr, "[!] Failed to receive tty.\n");
        exit(EXIT_FAILURE);
    }

    if(isatty(STDIN_FILENO)) {
        struct termios	termios;
        struct winsize	winsize;

        if(tcgetattr(STDIN_FILENO, &termios) >= 0 && ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) >= 0) {
            // turn off echo
            termios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
            termios.c_oflag &= ~(ONLCR);

            if(tcsetattr(tty_fd, TCSANOW, &termios) < 0 || ioctl(tty_fd, TIOCSWINSZ, &winsize) < 0) {
                fprintf(stderr, "[!] Warning! Failed to properly configure tty.\n");
            }
        }
    }

    spawn_relay(STDIN_FILENO, tty_fd);
    spawn_relay(tty_fd, STDOUT_FILENO);

    send_message(container->parent_signaling_fd, 0);
}

void container_start(container_t *container) {
    container_initialize_signaling_socket(container);
    container_spawn_child(container);
    container_finalize_signaling_socket_parent(container);
    container_initialize_user_namespace(container);

    send_message(container->parent_signaling_fd, 0);

//    container_spawn_network_relay(container);
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

