#define _GNU_SOURCE
#include "stdlib.h"
#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/capability.h>

#include "container/unsafe.h"

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
    cap_t capabilities = cap_get_proc();

    if(capabilities != NULL) {
        cap_set_flag(capabilities, CAP_INHERITABLE, sizeof(UNSAFE_CAPABILITIES), UNSAFE_CAPABILITIES, CAP_CLEAR);
        cap_set_proc(capabilities);
        cap_free(capabilities);
    }
}

void disable_unsafe_syscalls() {
    scmp_filter_ctx filter_ctx = seccomp_init(SCMP_ACT_ALLOW);

    if(filter_ctx != NULL) {
        // disallow new setuid and setgid binaries since these could have an effect outside the container
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));

        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));

        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));

        // don't allow new user namespaces since they could be used to regain the capabilities we dropped
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));

        // don't allow access to the kernel keyring since it is not namespaced
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0);

        // ptrace can be used to bypass seccomp
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);

        // NUMA is dangerous apparently ... I don't really understand, but Docker disables it
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0);
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(migrate_pages), 0);
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_pages), 0);
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(set_mempolicy), 0);

        // userfaultfd is rarely used and can be used to DoS the kernel
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(userfaultfd), 0);

        // perf_event_open isn't namespaced
        seccomp_rule_add(filter_ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);

        // don't allow setuid or setgid binaries to be executed with their permissions
        seccomp_attr_set(filter_ctx, SCMP_FLTATR_CTL_NNP, 0);

        // apply the filter to this process and all it's decedents
        seccomp_load(filter_ctx);

        seccomp_release(filter_ctx);
    }
}
