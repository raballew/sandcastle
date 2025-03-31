#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

// Default settings
#define PORT 8080
#define CONTENT_DIR "/content"
#define MAX_PATH 1024
#define BUFFER_SIZE 8192

// Seccomp BPF definitions
struct sock_filter seccomp_filter[] = {
    // Validate architecture
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // Allow essential syscalls for our webserver
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_lseek, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getdents, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getdents64, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_stat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // Default: kill process
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog seccomp_prog = {
    .len = sizeof(seccomp_filter) / sizeof(seccomp_filter[0]),
    .filter = seccomp_filter,
};

// Function to set up namespaces
void setup_namespaces() {
    // Create new namespaces
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWPID) == -1) {
        perror("unshare failed");
        exit(EXIT_FAILURE);
    }

    // Make sure all mounts are private to avoid propagating to host
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE failed");
        exit(EXIT_FAILURE);
    }
    
    // Set dummy hostname
    if (sethostname("sandbox", 7) == -1) {
        perror("sethostname failed");
        exit(EXIT_FAILURE);
    }
}

// Set up user mapping for user namespace
void setup_user_mapping(uid_t real_uid, gid_t real_gid) {
    // Map current UID to 1000 inside the namespace
    uid_t sandbox_uid = 1000;
    gid_t sandbox_gid = 1000;

    // Deny setgroups
    int setgroups_fd = open("/proc/self/setgroups", O_WRONLY);
    if (setgroups_fd != -1) {
        if (write(setgroups_fd, "deny", 4) == -1) {
            perror("write to setgroups");
            exit(EXIT_FAILURE);
        }
        close(setgroups_fd);
    }
    
    // Set up GID mapping
    int gid_map_fd = open("/proc/self/gid_map", O_WRONLY);
    if (gid_map_fd == -1) {
        perror("open gid_map");
        exit(EXIT_FAILURE);
    }
    
    char gid_map[100];
    snprintf(gid_map, sizeof(gid_map), "%d %d 1\n", sandbox_gid, real_gid);
    if (write(gid_map_fd, gid_map, strlen(gid_map)) == -1) {
        perror("write to gid_map");
        exit(EXIT_FAILURE);
    }
    close(gid_map_fd);
    
    // Set up UID mapping
    int uid_map_fd = open("/proc/self/uid_map", O_WRONLY);
    if (uid_map_fd == -1) {
        perror("open uid_map");
        exit(EXIT_FAILURE);
    }
    
    char uid_map[100];
    snprintf(uid_map, sizeof(uid_map), "%d %d 1\n", sandbox_uid, real_uid);
    if (write(uid_map_fd, uid_map, strlen(uid_map)) == -1) {
        perror("write to uid_map");
        exit(EXIT_FAILURE);
    }
    close(uid_map_fd);
}

// Set up filesystem for sandboxed environment
void setup_filesystem(const char *content_dir) {
    // Create a tmpfs for /tmp
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m,mode=1777") == -1) {
        perror("mount tmpfs failed");
        exit(EXIT_FAILURE);
    }
    
    // Create directories in the sandbox
    mkdir("/tmp/content", 0755);
    
    // Mount the content directory to /tmp/content as read-only
    if (mount(content_dir, "/tmp/content", NULL, MS_BIND | MS_RDONLY, NULL) == -1) {
        perror("mount content dir failed");
        exit(EXIT_FAILURE);
    }
    
    // Remount to enforce read-only
    if (mount(content_dir, "/tmp/content", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == -1) {
        perror("remount content dir read-only failed");
        exit(EXIT_FAILURE);
    }
    
    // Chroot to /tmp
    if (chroot("/tmp") == -1) {
        perror("chroot failed");
        exit(EXIT_FAILURE);
    }
    
    // Change to content directory
    if (chdir("/content") == -1) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }
}

// Drop privileges permanently
void drop_privileges() {
    // Disable privilege escalation
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl PR_SET_NO_NEW_PRIVS failed");
        exit(EXIT_FAILURE);
    }
    
    // Drop all capabilities
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data[2];
    
    memset(&cap_header, 0, sizeof(cap_header));
    memset(&cap_data, 0, sizeof(cap_data));
    
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = 0;
    
    if (capset(&cap_header, cap_data) == -1) {
        perror("capset failed");
        exit(EXIT_FAILURE);
    }
    
    // Set umask to restrict file creation permissions
    umask(0077);
}

// Apply seccomp BPF filter
void apply_seccomp() {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog) == -1) {
        perror("prctl PR_SET_SECCOMP failed");
        exit(EXIT_FAILURE);
    }
}

// Get MIME type based on file extension
const char* get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext == NULL) return "application/octet-stream";
    
    ext++; // Skip the '.'
    
    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0) {
        return "text/html";
    } else if (strcasecmp(ext, "txt") == 0) {
        return "text/plain";
    } else if (strcasecmp(ext, "css") == 0) {
        return "text/css";
    } else if (strcasecmp(ext, "js") == 0) {
        return "application/javascript";
    } else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(ext, "png") == 0) {
        return "image/png";
    } else if (strcasecmp(ext, "gif") == 0) {
        return "image/gif";
    } else if (strcasecmp(ext, "pdf") == 0) {
        return "application/pdf";
    }
    
    return "application/octet-stream";
}

// Handle HTTP request and serve file
void handle_request(int client_fd) {
    char buffer[BUFFER_SIZE];
    char path[MAX_PATH];
    
    // Read HTTP request
    ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
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
    
    char method[10], uri[MAX_PATH], version[10];
    if (sscanf(request_line, "%s %s %s", method, uri, version) != 3) {
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // Check if the request method is GET
    if (strcmp(method, "GET") != 0) {
        const char *response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Sanitize the URI
    if (uri[0] != '/') {
        const char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Convert URI to file path
    if (strcmp(uri, "/") == 0) {
        strcpy(path, "index.html");
    } else {
        // Remove the leading '/'
        strcpy(path, uri + 1);
    }
    
    // Check for path traversal attempts
    if (strstr(path, "..") != NULL) {
        const char *response = "HTTP/1.1 403 Forbidden\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Open the requested file
    int file_fd = open(path, O_RDONLY);
    if (file_fd == -1) {
        const char *response = "HTTP/1.1 404 Not Found\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
        exit(EXIT_SUCCESS);
    }
    
    // Get file size
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) == -1) {
        close(file_fd);
        const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // Prepare and send HTTP response header
    const char *mime_type = get_mime_type(path);
    char response_header[BUFFER_SIZE];
    snprintf(response_header, BUFFER_SIZE,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n",
        mime_type, file_stat.st_size);
    
    write(client_fd, response_header, strlen(response_header));
    
    // Send file content
    ssize_t bytes_sent;
    while ((bytes_read = read(file_fd, buffer, BUFFER_SIZE)) > 0) {
        bytes_sent = write(client_fd, buffer, bytes_read);
        if (bytes_sent != bytes_read) {
            break;
        }
    }
    
    close(file_fd);
    close(client_fd);
    exit(EXIT_SUCCESS);
}

// Main function
int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pid_t child_pid;
    const char *content_dir = (argc > 1) ? argv[1] : CONTENT_DIR;
    int port = (argc > 2) ? atoi(argv[2]) : PORT;
    
    // Save real UID and GID before any privilege changes
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    
    // Check if we're running as root
    if (real_uid != 0) {
        fprintf(stderr, "This program must be run as root for full sandboxing.\n");
        exit(EXIT_FAILURE);
    }
    
    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server running on port %d, serving content from %s\n", port, content_dir);
    
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
            setup_namespaces();
            setup_user_mapping(real_uid, real_gid);
            setup_filesystem(content_dir);
            drop_privileges();
            apply_seccomp();
            
            // Handle the HTTP request
            handle_request(client_fd);
            // Child process exits in handle_request
        } else {
            // Parent process
            close(client_fd);
            // No need to wait for child as it will become a zombie that gets reaped automatically
        }
    }
    
    close(server_fd);
    return 0;
} 