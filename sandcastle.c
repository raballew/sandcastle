#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "sandcastle.h"
#include "config.h"
#include "server.h"

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    return sandcastle_main(argc, argv);
}

/**
 * Main sandcastle application
 */
int sandcastle_main(int argc, char *argv[]) {
    int server_fd;
    
    // Initialize configuration with defaults
    SandcastleConfig config = config_init();
    
    // Parse command line arguments
    if (config_parse_args(&config, argc, argv) != 0) {
        return EXIT_FAILURE;
    }
    
    // Save real UID and GID before any privilege changes
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    
    // Check if we're running as root
    if (real_uid != 0) {
        fprintf(stderr, "This program must be run as root for full sandboxing.\n");
        return EXIT_FAILURE;
    }
    
    // Initialize HTTP server
    server_fd = server_init(&config);
    if (server_fd == -1) {
        return EXIT_FAILURE;
    }
    
    // Run server main loop (doesn't return unless error)
    if (server_run(server_fd, &config, real_uid, real_gid) != 0) {
        return EXIT_FAILURE;
    }
    
    // Should never reach here
    close(server_fd);
    return EXIT_SUCCESS;
} 