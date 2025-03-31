# Sandcastle

This is a minimal webserver in C that implements self-sandboxing mechanisms. For each client connection, the server creates a new process with strong security isolation.

## Security Features

- **Linux Namespaces**: Uses user, mount, IPC, UTS, and PID namespaces for isolation
- **Seccomp BPF Filtering**: Restricts system calls using a BPF filter
- **File System Isolation**: Serves files from a read-only directory in a chroot environment
- **Privilege Dropping**: Permanently drops privileges and capabilities
- **New Process Per Connection**: Creates an isolated process for each connection

## Requirements

- Linux system with kernel ≥ 3.8 (for user namespaces)
- Root privileges to run the server (required for namespace creation)
- GCC and Make for compilation

## Compilation

Compile the webserver with:

```bash
gcc -o sandcastle sandcastle.c -lcap
```

## Usage

```bash
sudo ./sandcastle [content_directory] [port]
```

Where:
- `content_directory` is the path to the directory containing static files to serve (default: /content)
- `port` is the port number to listen on (default: 8080)

Example:
```bash
# Create a directory with content to serve
mkdir -p /var/www/html
echo '<html><body><h1>Hello, World!</h1></body></html>' > /var/www/html/index.html

# Run the server
sudo ./sandcastle /var/www/html 8080
```

## Security Notes

- The webserver must be run as root to create namespaces and set up the sandbox
- Once the connection handling process is sandboxed, it has minimal privileges
- Seccomp filtering restricts the system calls allowed within the sandbox
- Each client connection is handled in a separate isolated process

## Limitations

- Only serves static content (no CGI or dynamic content)
- Only handles GET requests
- No support for TLS/HTTPS
- No virtual hosts or advanced HTTP features
- Requires root to start (though child processes drop privileges)
