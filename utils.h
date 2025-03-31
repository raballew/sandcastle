#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

/**
 * Get the MIME type for a file based on its extension
 * @param path File path
 * @return MIME type string
 */
const char* utils_get_mime_type(const char *path);

/**
 * Check if a path contains potential directory traversal
 * @param path Path to check
 * @return 1 if path contains traversal, 0 otherwise
 */
int utils_is_path_traversal(const char *path);

/**
 * Convert URI to file path safely
 * @param uri Input URI
 * @param path Output path buffer
 * @param max_path Maximum path length
 * @return 0 on success, -1 on failure
 */
int utils_uri_to_path(const char *uri, char *path, size_t max_path);

#endif /* UTILS_H */ 