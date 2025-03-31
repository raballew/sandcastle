#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define DEFAULT_PORT 8080
#define DEFAULT_CONTENT_DIR "/content"
#define DEFAULT_BUFFER_SIZE 8192
#define DEFAULT_MAX_PATH 1024

/**
 * Initialize configuration with default values
 */
SandcastleConfig config_init(void) {
    SandcastleConfig config;
    
    config.port = DEFAULT_PORT;
    config.content_dir = DEFAULT_CONTENT_DIR;
    config.buffer_size = DEFAULT_BUFFER_SIZE;
    config.max_path = DEFAULT_MAX_PATH;
    
    return config;
}

/**
 * Parse command line arguments into configuration
 */
int config_parse_args(SandcastleConfig *config, int argc, char *argv[]) {
    if (!config) {
        return -1;
    }
    
    // Parse command line arguments
    if (argc > 1) {
        config->content_dir = argv[1];
    }
    
    if (argc > 2) {
        char *endptr;
        int port = strtol(argv[2], &endptr, 10);
        
        if (*endptr != '\0' || port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            return -1;
        }
        
        config->port = port;
    }
    
    return 0;
}

/**
 * Print usage information
 */
void config_print_usage(void) {
    printf("Usage: sandcastle [content_dir] [port]\n");
    printf("  content_dir: Directory containing web content (default: %s)\n", DEFAULT_CONTENT_DIR);
    printf("  port: Port to listen on (default: %d)\n", DEFAULT_PORT);
} 