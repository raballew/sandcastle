#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "config.h"

/**
 * Initialize HTTP server with given configuration
 * @param config Server configuration
 * @return Server socket file descriptor or -1 on error
 */
int http_server_init(const SandcastleConfig *config);

/**
 * Run the HTTP server main loop
 * @param server_fd Server socket file descriptor
 * @param config Server configuration
 * @param uid Real user ID for sandboxing
 * @param gid Real group ID for sandboxing
 * @return Never returns unless error (returns -1)
 */
int http_server_run(int server_fd, const SandcastleConfig *config, uid_t uid, gid_t gid);

/**
 * Handle a single HTTP request
 * @param client_fd Client socket file descriptor
 * @param config Server configuration
 * @return 0 on success, -1 on error
 * Note: This function is called in a child process and should exit the process
 */
int http_handle_request(int client_fd, const SandcastleConfig *config);

/**
 * Send HTTP response with status code and message
 * @param client_fd Client socket file descriptor
 * @param status_code HTTP status code
 * @param status_message HTTP status message
 * @param content_type Content type (MIME)
 * @param body Response body (can be NULL)
 * @param body_length Length of response body
 * @return Bytes sent or -1 on error
 */
ssize_t http_send_response(int client_fd, int status_code, const char *status_message,
                          const char *content_type, const char *body, size_t body_length);

/**
 * Send error response with appropriate status code
 * @param client_fd Client socket file descriptor
 * @param status_code HTTP status code
 * @param status_message HTTP status message
 * @return Bytes sent or -1 on error
 */
ssize_t http_send_error(int client_fd, int status_code, const char *status_message);

#endif /* HTTP_SERVER_H */ 