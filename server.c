#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "server.h"
#include "sandbox.h"
#include "utils.h"

// Forward declarations
static int process_client_request(int client_fd, const SandcastleConfig *config);
static ssize_t send_response_headers(int client_fd, int status_code, const char *status_message,
                                 const char *content_type, const char *body, size_t body_length);
static ssize_t send_error_response(int client_fd, int status_code, const char *status_message);

/**
 * Initialize server with given configuration
 */
int server_init(const SandcastleConfig *config) {
    int server_fd;
    struct sockaddr_in server_addr;
    
    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->port);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }
    
    // Listen for connections
    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        close(server_fd);
        return -1;
    }
    
    printf("Server running on port %d, serving content from %s\n", config->port, config->content_dir);
    
    return server_fd;
}

/**
 * Run the server main loop
 */
int server_run(int server_fd, const SandcastleConfig *config, uid_t uid, gid_t gid) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    pid_t child_pid;
    int client_fd;

    // Main accept loop
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == -1) {
            perror("accept failed");
            continue;
        }
        
        // Fork a new process for each connection
        child_pid = fork();
        
        if (child_pid == -1) {
            perror("fork failed");
            close(client_fd);
            continue;
        }
        
        if (child_pid == 0) {
            // Child process
            close(server_fd);
            
            // Set up sandboxing for the child process
            if (sandbox_initialize(config->content_dir, uid, gid) != 0) {
                // Failed to set up sandbox
                close(client_fd);
                exit(EXIT_FAILURE);
            }
            
            // Handle the HTTP request
            process_client_request(client_fd, config);

            // We should never reach here
            exit(EXIT_FAILURE);
        } else {
            // Parent process
            close(client_fd);
            // No need to wait for child as it will become a zombie that gets reaped automatically
        }
    }
    
    // We should never reach here
    close(server_fd);
    return 0;
}

/**
 * Send HTTP response with status code and message
 */
static ssize_t send_response_headers(int client_fd, int status_code, const char *status_message,
                          const char *content_type, const char *body, size_t body_length) {
    char header[1024]; // Smaller fixed buffer - headers don't need to be large
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_message, content_type, body_length);
    
    ssize_t total_sent = 0;
    ssize_t sent = write(client_fd, header, header_len);
    if (sent <= 0) {
        return -1;
    }
    total_sent += sent;
    
    if (body && body_length > 0) {
        sent = write(client_fd, body, body_length);
        if (sent <= 0) {
            return -1;
        }
        total_sent += sent;
    }

    return total_sent;
}

/**
 * Send error response with appropriate status code
 */
static ssize_t send_error_response(int client_fd, int status_code, const char *status_message) {
    return send_response_headers(client_fd, status_code, status_message, 
                            "text/plain", status_message, strlen(status_message));
}

/**
 * Handle a single HTTP request
 */
static int process_client_request(int client_fd, const SandcastleConfig *config) {
    char buffer[config->buffer_size];
    char path[config->max_path];
    
    // Read HTTP request
    ssize_t bytes_read = read(client_fd, buffer, config->buffer_size - 1);
    if (bytes_read <= 0) {
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    buffer[bytes_read] = '\0';
    
    // Parse HTTP request to get path
    char *request_line = strtok(buffer, "\r\n");
    if (request_line == NULL) {
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // Parse request line
    char method[10], uri[config->max_path], version[10];
    if (sscanf(request_line, "%9s %1023s %9s", method, uri, version) != 3) {
        send_error_response(client_fd, 400, "Bad Request");
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Check if the request method is GET
    if (strcmp(method, "GET") != 0) {
        send_error_response(client_fd, 405, "Method Not Allowed");
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Convert URI to file path
    if (utils_uri_to_path(uri, path, config->max_path) != 0) {
        send_error_response(client_fd, 400, "Bad Request");
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Open the requested file
    int file_fd = open(path, O_RDONLY);
    if (file_fd == -1) {
        send_error_response(client_fd, 404, "Not Found");
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Get file size
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) == -1) {
        close(file_fd);
        send_error_response(client_fd, 500, "Internal Server Error");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // Get MIME type and send headers
    const char *mime_type = utils_get_mime_type(path);
    send_response_headers(client_fd, 200, "OK", mime_type, NULL, file_stat.st_size);
    
    // Send file content
    while ((bytes_read = read(file_fd, buffer, config->buffer_size)) > 0) {
        if (write(client_fd, buffer, bytes_read) != bytes_read) {
            break;
        }
    }
    
    close(file_fd);
    close(client_fd);
    exit(EXIT_SUCCESS);
    
    return 0; // Never reached, but keeps compiler happy
} 