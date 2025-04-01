#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include "sandbox.h"

// Forward declarations
static int sandbox_create_namespaces(void);
static int sandbox_isolate_mounts(void);
static int sandbox_set_hostname(void);
static int sandbox_configure_namespaces(void);
static int sandbox_deny_setgroups(void);
static int sandbox_map_gid(gid_t real_gid, gid_t sandbox_gid);
static int sandbox_map_uid(uid_t real_uid, uid_t sandbox_uid);
static int sandbox_configure_user_mapping(uid_t real_uid, gid_t real_gid);
static int sandbox_create_tmpfs(void);
static int sandbox_create_directories(void);
static int sandbox_mount_content(const char *content_dir);
static int sandbox_apply_chroot(void);
static int sandbox_configure_filesystem(const char *content_dir);
static int sandbox_disable_privilege_escalation(void);
static int sandbox_drop_capabilities(void);
static int sandbox_configure_privileges(void);
static int sandbox_apply_seccomp_filter(void);

// Seccomp BPF definitions
struct sock_filter seccomp_filter[] = {
    // Validate architecture
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // Allow essential syscalls for our webserver
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_lseek, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_stat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // Default: kill process
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog seccomp_prog = {
    .len = sizeof(seccomp_filter) / sizeof(seccomp_filter[0]),
    .filter = seccomp_filter,
};

/**
 * Create new namespaces for isolation
 */
static int sandbox_create_namespaces(void) {
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWPID) == -1) {
        perror("unshare failed");
        return -1;
    }
    return 0;
}

/**
 * Make mounts private to prevent propagation to host
 */
static int sandbox_isolate_mounts(void) {
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE failed");
        return -1;
    }
    return 0;
}

/**
 * Set hostname for the sandbox
 */
static int sandbox_set_hostname(void) {
    if (sethostname("sandbox", 7) == -1) {
        perror("sethostname failed");
        return -1;
    }
    return 0;
}

/**
 * Initialize and setup namespaces for isolation
 */
static int sandbox_configure_namespaces(void) {
    if (sandbox_create_namespaces() != 0) {
        return -1;
    }

    if (sandbox_isolate_mounts() != 0) {
        return -1;
    }
    
    if (sandbox_set_hostname() != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Deny setgroups to prevent privilege escalation
 */
static int sandbox_deny_setgroups(void) {
    int setgroups_fd = open("/proc/self/setgroups", O_WRONLY);
    if (setgroups_fd != -1) {
        if (write(setgroups_fd, "deny", 4) == -1) {
            perror("write to setgroups");
            close(setgroups_fd);
            return -1;
        }
        close(setgroups_fd);
    }
    return 0;
}

/**
 * Setup GID mapping
 */
static int sandbox_map_gid(gid_t real_gid, gid_t sandbox_gid) {
    int gid_map_fd = open("/proc/self/gid_map", O_WRONLY);
    if (gid_map_fd == -1) {
        perror("open gid_map");
        return -1;
    }
    
    char gid_map[100];
    snprintf(gid_map, sizeof(gid_map), "%d %d 1\n", sandbox_gid, real_gid);
    if (write(gid_map_fd, gid_map, strlen(gid_map)) == -1) {
        perror("write to gid_map");
        close(gid_map_fd);
        return -1;
    }
    close(gid_map_fd);
    
    return 0;
}

/**
 * Setup UID mapping
 */
static int sandbox_map_uid(uid_t real_uid, uid_t sandbox_uid) {
    int uid_map_fd = open("/proc/self/uid_map", O_WRONLY);
    if (uid_map_fd == -1) {
        perror("open uid_map");
        return -1;
    }
    
    char uid_map[100];
    snprintf(uid_map, sizeof(uid_map), "%d %d 1\n", sandbox_uid, real_uid);
    if (write(uid_map_fd, uid_map, strlen(uid_map)) == -1) {
        perror("write to uid_map");
        close(uid_map_fd);
        return -1;
    }
    close(uid_map_fd);
    
    return 0;
}

/**
 * Setup user mapping for user namespace
 */
static int sandbox_configure_user_mapping(uid_t real_uid, gid_t real_gid) {
    // Map current UID to 1000 inside the namespace
    uid_t sandbox_uid = 1000;
    gid_t sandbox_gid = 1000;

    if (sandbox_deny_setgroups() != 0) {
        return -1;
    }
    
    if (sandbox_map_gid(real_gid, sandbox_gid) != 0) {
        return -1;
    }
    
    if (sandbox_map_uid(real_uid, sandbox_uid) != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Setup temporary filesystem with tmpfs
 */
static int sandbox_create_tmpfs(void) {
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m,mode=1777") == -1) {
        perror("mount tmpfs failed");
        return -1;
    }
    return 0;
}

/**
 * Create necessary directories in the sandbox
 */
static int sandbox_create_directories(void) {
    if (mkdir("/tmp/content", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /tmp/content failed");
        return -1;
    }
    return 0;
}

/**
 * Mount content directory as read-only
 */
static int sandbox_mount_content(const char *content_dir) {
    // Mount the content directory to /tmp/content as read-only
    if (mount(content_dir, "/tmp/content", NULL, MS_BIND | MS_RDONLY, NULL) == -1) {
        perror("mount content dir failed");
        return -1;
    }
    
    // Remount to enforce read-only
    if (mount(content_dir, "/tmp/content", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == -1) {
        perror("remount content dir read-only failed");
        return -1;
    }
    
    return 0;
}

/**
 * Perform chroot to /tmp and change working directory
 */
static int sandbox_apply_chroot(void) {
    // Chroot to /tmp
    if (chroot("/tmp") == -1) {
        perror("chroot failed");
        return -1;
    }
    
    // Change to content directory
    if (chdir("/content") == -1) {
        perror("chdir failed");
        return -1;
    }
    
    return 0;
}

/**
 * Setup filesystem for sandboxed environment
 */
static int sandbox_configure_filesystem(const char *content_dir) {
    if (sandbox_create_tmpfs() != 0) {
        return -1;
    }
    
    if (sandbox_create_directories() != 0) {
        return -1;
    }
    
    if (sandbox_mount_content(content_dir) != 0) {
        return -1;
    }
    
    if (sandbox_apply_chroot() != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Disable privilege escalation
 */
static int sandbox_disable_privilege_escalation(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl PR_SET_NO_NEW_PRIVS failed");
        return -1;
    }
    return 0;
}

/**
 * Drop all capabilities
 */
static int sandbox_drop_capabilities(void) {
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data[2];
    
    memset(&cap_header, 0, sizeof(cap_header));
    memset(&cap_data, 0, sizeof(cap_data));
    
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = 0;
    
    if (capset(&cap_header, cap_data) == -1) {
        perror("capset failed");
        return -1;
    }
    
    return 0;
}

/**
 * Drop privileges permanently
 */
static int sandbox_configure_privileges(void) {
    if (sandbox_disable_privilege_escalation() != 0) {
        return -1;
    }
    
    if (sandbox_drop_capabilities() != 0) {
        return -1;
    }
    
    // Set umask to restrict file creation permissions
    umask(0077);
    
    return 0;
}

/**
 * Apply seccomp BPF filter
 */
static int sandbox_apply_seccomp_filter(void) {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog) == -1) {
        perror("prctl PR_SET_SECCOMP failed");
        return -1;
    }
    
    return 0;
}

/**
 * Initialize the complete sandbox environment
 * 
 * This function sets up namespaces, user mapping, filesystem,
 * drops privileges, and applies seccomp filters.
 * 
 * @param content_dir Directory containing web content
 * @param real_uid Real user ID
 * @param real_gid Real group ID
 * @return 0 on success, -1 on error
 */
int sandbox_initialize(const char *content_dir, uid_t real_uid, gid_t real_gid) {
    if (sandbox_configure_namespaces() != 0) {
        fprintf(stderr, "Failed to set up namespaces\n");
        return -1;
    }
    
    if (sandbox_configure_user_mapping(real_uid, real_gid) != 0) {
        fprintf(stderr, "Failed to set up user mapping\n");
        return -1;
    }
    
    if (sandbox_configure_filesystem(content_dir) != 0) {
        fprintf(stderr, "Failed to set up filesystem\n");
        return -1;
    }
    
    if (sandbox_configure_privileges() != 0) {
        fprintf(stderr, "Failed to drop privileges\n");
        return -1;
    }
    
    if (sandbox_apply_seccomp_filter() != 0) {
        fprintf(stderr, "Failed to apply seccomp filter\n");
        return -1;
    }
    
    return 0;
} 