#ifndef SANDBOX_H
#define SANDBOX_H

#include <linux/filter.h>
#include <sys/types.h>

/**
 * Seccomp filter program structure and definitions
 */
extern struct sock_filter seccomp_filter[];
extern struct sock_fprog seccomp_prog;

/**
 * Initialize and setup namespaces for isolation
 * @return 0 on success, -1 on error
 */
int sandbox_setup_namespaces(void);

/**
 * Setup user mapping for user namespace
 * @param real_uid Real user ID
 * @param real_gid Real group ID
 * @return 0 on success, -1 on error
 */
int sandbox_setup_user_mapping(uid_t real_uid, gid_t real_gid);

/**
 * Setup filesystem for sandboxed environment
 * @param content_dir Directory containing web content
 * @return 0 on success, -1 on error
 */
int sandbox_setup_filesystem(const char *content_dir);

/**
 * Drop privileges permanently
 * @return 0 on success, -1 on error
 */
int sandbox_drop_privileges(void);

/**
 * Apply seccomp BPF filter
 * @return 0 on success, -1 on error
 */
int sandbox_apply_seccomp(void);

#endif /* SANDBOX_H */ 