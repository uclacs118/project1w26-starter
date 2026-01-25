#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);
// Helper function
int sendAll(SSL *ssl, const char *msg, size_t len);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    
    // docs say that SSL_library_init() is deprecated and always returns 1, also OpenSSL_add_ssl_algorithms() is a synonym for SSL_library_init()
    // https://wiki.openssl.org/index.php/Library_Initialization
    if (OPENSSL_init_ssl(0, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);

    // Loads the certificates and keys into the SSL_CTX object ctx
    // int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM ) <= 0) {
        fprintf(stderr, "Error: Failed to server key");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM ) <= 0) {
        fprintf(stderr, "Error: Failed to upload key");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Error: No matching certificate w/ Private Key\n");
        exit(EXIT_FAILURE);
    }
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

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
        
        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);
        // //int SSL_accept(SSL *ssl);
        // //SSL_in_init() returns 1 if the SSL/TLS state 
        // //machine is currently processing or awaiting handshake messages, or 0 otherwise.
        // SSL_in_connect_init(ssl); // Send the handshake as the client to server
        // while (SSL_get_state(ssl) == TLS_ST_OK);
        // // Handshake message sending/processing has completed
        // //Maybe have a time out fo this 
        // // Then we are going to accept the connection from the client
        // SSL_in_accept_init(ssl);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;  // or return; depending on your loop structure
        }

        //Sets the file descriptor fd as the input/output 
        //facility for the TLS/SSL (encrypted) side of ssl
        //Attach this SSL object to that socket so SSL knows where to read from and write to.
        if (SSL_set_fd(ssl, client_socket) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        if (SSL_accept(ssl) != 1) {   // perform TLS handshake (server side)
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        if (ssl != NULL) {
            handle_request(ssl);
        }
        
        // TODO: Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);

        
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
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

char *parseFileName(const char *fileName) {
    static char buffer[BUFFER_SIZE];
    size_t i = 0, j = 0;

    while (fileName[i] != '\0' && j < BUFFER_SIZE - 1) {
    if (strncmp(&fileName[i], "%20", 3) == 0) {
        buffer[j++] = ' ';
        i += 3;
    } 
    else {
        buffer[j++] = fileName[i++];
    }
    }
    buffer[j] = '\0';
    return buffer;
}
// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    char * parsedName;
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = 0;

    //int SSL_read(SSL *ssl, void *buf, int num);
    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    
    // THERE are no bytes read, if its greater than 0 operation was successful & it gives
    // Number of bytes read
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1); // Creates a new buffer called request
    strcpy(request, buffer); // Copies the request into the new buffer
    
    char *method = strtok(request, " "); // Parses request
    char *file_name = strtok(NULL, " "); // Parses the request
    file_name++;
    parsedName = parseFileName(file_name);
    if (strlen(parsedName) == 0) {
        strcat(parsedName, "index.html");
    }
    char *http_version = strtok(NULL, " ");
    printf("Sending local file %s\n", parsedName);
    if (file_exists(parsedName)) {
        printf("Sending local file %s\n", parsedName);
        send_local_file(ssl, parsedName);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

int sendAll(SSL *ssl, const char *msg, size_t len) {
    int total_sent = 0;
    const char * curr_pointer = msg;
    while (total_sent < len) {
        //int SSL_write(SSL *ssl, const void *buf, int num);
        int bytes_written = SSL_write(ssl, curr_pointer, (int)len - total_sent);
        if (bytes_written > 0) {
            // The write was successful
            curr_pointer += bytes_written;
            total_sent += bytes_written;
        }
        else {
            int err = SSL_get_error(ssl, bytes_written);
            fprintf(stderr, "SSL_write failed \n");
            return -1;
        }
    }
    return 0;
}

// TODO: Serve local file with correct Content-Type header
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
        // TODO: Send response via SSL
        //int SSL_write(SSL *ssl, const void *buf, int num);
        if (sendAll(ssl, response, strlen(response)) != 0) {
            return;
        }
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    }
    else if (strstr(path, ".txt")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".jpg")){
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg\r\n\r\n";
    }
    else{
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    if (sendAll(ssl, response, strlen(response)) != 0) {
        // Error in sending
        return; 
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        // Error in sending
        if (sendAll(ssl, buffer, bytes_read) != 0) {
            return;
        }
    }
    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        if (sendAll(ssl, buffer, (size_t)bytes_read) != 0) {
            // Error in sending
            return;
        }
    }
    close(remote_socket);
}
