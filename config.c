#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "config.h"

#define DEFAULT_PORT 8080
#define DEFAULT_CONTENT_DIR "/var/www/html"
#define DEFAULT_BUFFER_SIZE 8192
#define DEFAULT_MAX_PATH 1024

/**
 * Print usage information
 */
static void config_print_usage(void) {
    printf("Usage: sandcastle [OPTIONS]\n");
    printf("\nOptions:\n");
    printf("  -p, --port PORT      Port to listen on (default: %d)\n", DEFAULT_PORT);
    printf("  -d, --dir DIRECTORY  Directory containing web content (default: %s)\n", DEFAULT_CONTENT_DIR);
    printf("  -h, --help           Display this help message and exit\n");
} 

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
 * Parse command line arguments into configuration using getopt
 */
int config_parse_args(SandcastleConfig *config, int argc, char *argv[]) {
    if (!config) {
        return -1;
    }
    
    int opt;
    int port;
    char *endptr;
    
    // Define long options
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"dir", required_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Reset getopt
    optind = 0;
    
    // Suppress getopt error messages
    opterr = 0;
    
    // Parse command line arguments using getopt
    while ((opt = getopt_long(argc, argv, "p:d:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': // Port
                port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || port <= 0 || port > 65535) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    return -1;
                }
                config->port = port;
                break;
                
            case 'd': // Content directory
                config->content_dir = optarg;
                break;
                
            case 'h': // Help
                config_print_usage();
                exit(EXIT_SUCCESS);
                
            case '?': // Unknown option
                config_print_usage();
                return -1;
                
            default:
                // Shouldn't reach here
                break;
        }
    }
    
    // Check for any non-option arguments, which are not supported
    if (optind < argc) {
        config_print_usage();
        return -1;
    }
    
    return 0;
}