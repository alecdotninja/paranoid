#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdbool.h>

#include "container/signaling.h"

container_error_t container_signaling_initialize_pre_spawn(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->parent_signaling_fd >= 0 || container->child_signaling_fd >= 0) {
        return CONTAINER_ERROR_SANITY;
    }

    int signaling_fds[2];

    if(socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, signaling_fds)) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(fcntl(signaling_fds[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(signaling_fds[1], F_SETFD, FD_CLOEXEC) < 0) {
        close(signaling_fds[0]);
        close(signaling_fds[1]);

        return CONTAINER_ERROR_SYSTEM;
    }

    container->parent_signaling_fd = signaling_fds[0];
    container->child_signaling_fd = signaling_fds[1];

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_signaling_initialize_parent(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->child_signaling_fd < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    if(close(container->child_signaling_fd) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    container->child_signaling_fd = -1;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_signaling_initialize_child(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->parent_signaling_fd < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    if(close(container->parent_signaling_fd) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    container->parent_signaling_fd = -1;

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_signaling_finalize(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->parent_signaling_fd < 0 && container->child_signaling_fd < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    if(container->parent_signaling_fd >= 0) {
        if(close(container->parent_signaling_fd) >= 0) {
            container->parent_signaling_fd = -1;
        }else{
            return CONTAINER_ERROR_SYSTEM;
        }
    }

    if(container->child_signaling_fd >= 0) {
        if(close(container->child_signaling_fd) >= 0) {
            container->child_signaling_fd = -1;
        }else{
            return CONTAINER_ERROR_SYSTEM;
        }
    }

    return CONTAINER_ERROR_OKAY;
}

static int container_signaling_fd(container_t *container) {
    if(container == NULL) {
        return -1;
    }

    if(container->parent_signaling_fd >= 0 && container->child_signaling_fd < 0) {
        return container->parent_signaling_fd;
    }

    if(container->child_signaling_fd >= 0 && container->parent_signaling_fd < 0) {
        return container->child_signaling_fd;
    }

    return -1;
}

container_error_t container_signaling_sync(container_t *container) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    int signaling_fd;

    if((signaling_fd = container_signaling_fd(container)) < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    int out_msg = 2;
    int in_msg = 1;

    if(write(signaling_fd, &out_msg, sizeof(out_msg)) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(read(signaling_fd, &in_msg, sizeof(in_msg)) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(out_msg != in_msg) {
        return CONTAINER_ERROR_SANITY;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_signaling_sync_send_fd(container_t *container, int *fd) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    int signaling_fd;

    if((signaling_fd = container_signaling_fd(container)) < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    int out_msg = 2;
    int in_msg = 1;

    struct msghdr msgh;
    struct iovec iov;

    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmhp;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    iov.iov_base = &out_msg;
    iov.iov_len = sizeof(out_msg);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    cmhp = CMSG_FIRSTHDR(&msgh);
    cmhp->cmsg_len = CMSG_LEN(sizeof(int));
    cmhp->cmsg_level = SOL_SOCKET;
    cmhp->cmsg_type = SCM_RIGHTS;
    *((int *) CMSG_DATA(cmhp)) = *fd;

    if(sendmsg(signaling_fd, &msgh, 0)) {
        return CONTAINER_ERROR_SYSTEM;
    }

    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_RIGHTS;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &in_msg;
    iov.iov_len = sizeof(in_msg);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    if(recvmsg(signaling_fd, &msgh, 0) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    if(out_msg != in_msg) {
        return CONTAINER_ERROR_SANITY;
    }

    return CONTAINER_ERROR_OKAY;
}

container_error_t container_signaling_sync_recv_fd(container_t *container, int *fd) {
    if(container == NULL) {
        return CONTAINER_ERROR_SANITY;
    }

    int signaling_fd;

    if((signaling_fd = container_signaling_fd(container)) < 0) {
        return CONTAINER_ERROR_SANITY;
    }

    int out_msg = 2;
    int in_msg = 1;

    struct msghdr msgh;
    struct iovec iov;

    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmhp;

    msgh.msg_iov = NULL;
    msgh.msg_iovlen = 0;

    iov.iov_base = &out_msg;
    iov.iov_len = sizeof(out_msg);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    if(sendmsg(signaling_fd, &msgh, 0)) {
        return CONTAINER_ERROR_SYSTEM;
    }

    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_RIGHTS;

    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &in_msg;
    iov.iov_len = sizeof(in_msg);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    if(recvmsg(signaling_fd, &msgh, 0) < 0) {
        return CONTAINER_ERROR_SYSTEM;
    }

    cmhp = CMSG_FIRSTHDR(&msgh);
    if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(int)))
        return CONTAINER_ERROR_SANITY;
    if (cmhp->cmsg_level != SOL_SOCKET)
        return CONTAINER_ERROR_SANITY;
    if (cmhp->cmsg_type != SCM_RIGHTS)
        return CONTAINER_ERROR_SANITY;

    if(out_msg != in_msg) {
        return CONTAINER_ERROR_SANITY;
    }

    *fd = *((int *) CMSG_DATA(cmhp));

    return CONTAINER_ERROR_OKAY;
}
