#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

const int BUFFER_SIZE = 1024;
int LOCAL_PORT_TO_CLIENT = 8443;
char* REMOTE_HOST = "127.0.0.1";
int REMOTE_PORT = 5001;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// DONE: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0) {
            LOCAL_PORT_TO_CLIENT = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-r") == 0) {
            REMOTE_HOST = argv[i + 1];
        } else if (strcmp(argv[i], "-p") == 0) {
            REMOTE_PORT = atoi(argv[i + 1]);
        }
    }
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // DONE: Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // DONE: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load certificate: %s\n", "server.crt");
        exit(1);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load private key: %s\n", "server.key");
        exit(1);
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // DONE: Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new failed\n");
            close(client_socket);
            continue;
        }

        if (SSL_set_fd(ssl, client_socket) == 0) {
            fprintf(stderr, "SSL_set_fd failed\n");
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL_accept failed\n");
            ERR_print_errors_fp(stderr);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
            
        if (ssl != NULL) {
            handle_request(ssl);
        }
        
        // DONE: Clean up SSL connection
        
        SSL_shutdown(ssl);
        SSL_free(ssl);

        close(client_socket);
    }

    close(server_socket);
    // DONE: Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// handle % and spaces in the file path
void url_decode(char *dst, const char *src) {
    while (*src) {
        if (*src == '%') {
            if (src[1] && src[2]) {
                char hex[3] = {src[1], src[2], '\0'};
                int value;
                sscanf(hex, "%x", &value);
                
                *dst++ = (char)value;
                src += 3;
            } else {
                *dst++ = *src++;
            }
        } else if (*src == '+') {
            *dst++ = ' '; 
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0'; 
}

// DONE: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // DONE: Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    
    char *method = strtok(request, " ");
    char *path = strtok(NULL, " ");
    char file_name[256];
    url_decode(file_name, path + 1);

    if (strlen(file_name) == 0) {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

// DONE: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        
        // DONE: Send response via SSL
        SSL_write(ssl, response, strlen(response));
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".txt")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".jpg")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg\r\n\r\n";
    } else if (strstr(path, ".m3u8")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/vnd.apple.mpegurl\r\n\r\n";
    } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n";
    }

    // DONE: Send response header and file content via SSL
    SSL_write(ssl, response, strlen(response));

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // DONE: Send file data via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    fclose(file);
}

// DONE: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        const char *bad_gateway = 
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n\r\n"
            "Content-Length: 113\r\n"
            "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
            "<body><h1>502 Bad Gateway</h1></body></html>";
        SSL_write(ssl, bad_gateway, strlen(bad_gateway));
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        const char *bad_gateway = 
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n\r\n"
            "Content-Length: 113\r\n"
            "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
            "<body><h1>502 Bad Gateway</h1></body></html>";
        SSL_write(ssl, bad_gateway, strlen(bad_gateway));
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // DONE: Forward response to client via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    close(remote_socket);
}
