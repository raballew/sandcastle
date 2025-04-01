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
int sandbox_initialize(const char *content_dir, uid_t real_uid, gid_t real_gid);

#endif /* SANDBOX_H */ 