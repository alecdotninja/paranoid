#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "container/signaling.h"

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
