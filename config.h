#ifndef CONFIG_H
#define CONFIG_H

/**
 * Configuration structure for Sandcastle
 */
typedef struct {
    int port;                  // Port number for HTTP server
    const char *content_dir;   // Directory with content to serve
    int buffer_size;           // Buffer size for I/O operations
    int max_path;              // Maximum path length
} SandcastleConfig;

/**
 * Initialize configuration with default values
 * @return Initialized config structure
 */
SandcastleConfig config_init(void);

/**
 * Parse command line arguments into configuration
 * @param config Pointer to configuration structure
 * @param argc Command line argument count
 * @param argv Command line argument values
 * @return 0 on success, -1 on failure
 */
int config_parse_args(SandcastleConfig *config, int argc, char *argv[]);

#endif /* CONFIG_H */ 