#ifndef SERVER_H
#define SERVER_H

#include "config.h"

/**
 * Initialize server with given configuration
 * @param config Server configuration
 * @return Server socket file descriptor or -1 on error
 */
int server_init(const SandcastleConfig *config);

/**
 * Run the server main loop
 * @param server_fd Server socket file descriptor
 * @param config Server configuration
 * @param uid Real user ID for sandboxing
 * @param gid Real group ID for sandboxing
 * @return Never returns unless error (returns -1)
 */
int server_run(int server_fd, const SandcastleConfig *config, uid_t uid, gid_t gid);

#endif /* SERVER_H */ 