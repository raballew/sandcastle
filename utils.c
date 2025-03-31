#include <string.h>
#include "utils.h"

/**
 * Get the MIME type for a file based on its extension
 */
const char* utils_get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    
    ext++; // Skip the '.'
    
    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html";
    if (!strcasecmp(ext, "css")) return "text/css";
    if (!strcasecmp(ext, "txt")) return "text/plain";
    
    return "application/octet-stream";
}

/**
 * Check if a path contains potential directory traversal
 */
int utils_is_path_traversal(const char *path) {
    return (strstr(path, "..") != NULL);
}

/**
 * Convert URI to file path safely
 */
int utils_uri_to_path(const char *uri, char *path, size_t max_path) {
    if (!uri || !path || max_path == 0) {
        return -1;
    }
    
    // Check if URI is properly formatted
    if (uri[0] != '/') {
        return -1;
    }
    
    // Convert URI to file path
    if (strcmp(uri, "/") == 0) {
        if (strlen("index.html") >= max_path) {
            return -1;
        }
        strncpy(path, "index.html", max_path);
        path[max_path - 1] = '\0';
    } else {
        // Remove the leading '/'
        if (strlen(uri + 1) >= max_path) {
            return -1;
        }
        strncpy(path, uri + 1, max_path);
        path[max_path - 1] = '\0';
    }
    
    // Check for path traversal
    if (utils_is_path_traversal(path)) {
        return -1;
    }
    
    return 0;
} 