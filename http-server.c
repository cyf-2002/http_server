#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define BUFFER_SIZE 1024
#define CERT_FILE "/home/cyf02/Desktop/04-http_server/keys/cnlab.cert"
#define KEY_FILE "/home/cyf02/Desktop/04-http_server/keys/cnlab.prikey"

struct ThreadArgs {
    int port;
    SSL_CTX* ssl_context;
};

char* read_file_range(const char* filename, size_t start, size_t end) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, start, SEEK_SET);

    size_t size = end - start + 1;
    char* content = (char*)malloc(size);
    if (!content) {
        perror("Error allocating memory");
        fclose(file);
        return NULL;
    }

    fread(content, 1, size, file);

    fclose(file);
    return content;
}

void handle_http_request(int client_socket) {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received < 0) {
        perror("Error receiving data");
        close(client_socket);
        return;
    }

    buffer[bytes_received] = '\0';

    char method[10];
    char requested_resource[256];

    if (sscanf(buffer, "%s %s", method, requested_resource) != 2) {
        fprintf(stderr, "Invalid HTTP request format\n");
        close(client_socket);
        return;
    }


    // HTTPS URL
    const char* https_url = "https://10.0.0.1";  

    // 301 Moved Permanently
    char moved_response[1024];
    snprintf(moved_response, sizeof(moved_response),
            "HTTP/1.1 301 Moved Permanently\r\nLocation: %s%s\r\nContent-Type: text/plain\r\n\r\nResource moved permanently. Please use the HTTPS URL.", 
            https_url, requested_resource);
    send(client_socket, moved_response, sizeof(moved_response), 0);

    printf("关闭client_socket\n");
    close(client_socket);
}

size_t get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("sizefile:%zu", (size_t)st.st_size);
        return (size_t)st.st_size;
    }
    return 0;  // 返回0表示获取文件大小失败
}

void handle_https_request(int client_socket, SSL_CTX* ssl_context) {
    // 处理 HTTPS 请求
    SSL* ssl = SSL_new(ssl_context);
    SSL_set_fd(ssl, client_socket);
    SSL_accept(ssl); 

    // 接收请求头
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    printf("Received HTTPS request:\n%s\n", buffer);

    // 抓取请求方法和请求资源
    char method[10];
    char requested_resource[256];

    if (sscanf(buffer, "%s %s", method, requested_resource) != 2) {
        fprintf(stderr, "Invalid HTTPS request format\n");
        close(client_socket);
        return;
    }

    if (strcmp(method, "GET") != 0) {
        fprintf(stderr, "Unsupported HTTPS method: %s\n", method);
        close(client_socket);
        return;
    }

    // 组合文件路径
    const char* base_folder = "/home/cyf02/Desktop/04-http_server";  // Change this to the path of your folder
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "%s%s", base_folder, requested_resource);

    const char* header;
    const char* response_body;

    printf("request resource:%s\n", full_path);
    FILE* file = fopen(full_path, "rb");
    if (!file) {
        // 文件不存在
        header = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n";
        response_body = "Not Found";
        // 发送响应
        char full_response[1024];
        snprintf(full_response, sizeof(full_response), "%s\r\n%s\r\n", header, response_body);
        SSL_write(ssl, full_response, strlen(full_response));

        // 关闭 SSL 连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    const size_t chunk_size = 1024;
    char* range_header = strstr(buffer, "Range: bytes=");
    // 范围请求
    if (range_header != NULL) {
        size_t start, end = -1;
        sscanf(range_header + strlen("Range: bytes="), "%zu-%zu", &start, &end);

        // 如果范围请求的 end 为空，将其设置为文件末尾的位置
        if (end == -1) {
            size_t file_size = get_file_size(full_path);
            end = file_size - 1;
        }
        // 分段读取
        char* file_content = read_file_range(full_path, start, end);
        if (file_content) {
            char response_header[1024];
            snprintf(response_header, sizeof(response_header),
                    "HTTP/1.1 206 Partial Content\r\nContent-Type: text/html\r\nContent-Range: bytes %zu-%zu/%zu\r\n\r\n",
                    start, end, end + 1);

            ssize_t header_sent = SSL_write(ssl, response_header, strlen(response_header));
            if (header_sent < 0) {
                perror("Error sending response header");
                free(file_content);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                return;
            }

            // 发送file
            SSL_write(ssl, file_content, end - start + 1);
            free(file_content);
        } 
    } else {
        // 全部请求
        char response_header[1024];
        snprintf(response_header, sizeof(response_header),
             "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n");
        SSL_write(ssl, response_header, strlen(response_header));
        
        char chunk_buffer[1024];
        size_t bytes_read;

        while ((bytes_read = fread(chunk_buffer, 1, sizeof(chunk_buffer), file)) > 0) {
            char chunk_size[32];
            snprintf(chunk_size, sizeof(chunk_size), "%zx\r\n", bytes_read);
            SSL_write(ssl, chunk_size, strlen(chunk_size));
            SSL_write(ssl, chunk_buffer, bytes_read);
            SSL_write(ssl, "\r\n", 2);
        }
        SSL_write(ssl, "0\r\n\r\n", 5);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void* http_server(void* port) {
    int server_socket, client_socket;
    /*定义IPV4套接字地址结构体addr*/
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int port_number = *((int*)port);

    /*创建套接字，AF_INET表示IPV4协议族 SOCK_STREAM表示面向连接的字节流（TCP协议），0表示默认使用TCP协议类型*/
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    // 设置addr的端口号为80（需要用htons()函数进行主机序转网络序）
    server_addr.sin_port = htons(port_number);

    /*把创建的socket与指定的地址（IP和端口号）绑定起来，如果失败*/
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }
    printf("bind success\n");

    /*准备监听，使该进程能够接收客户端连接请求，10表示连接请求队列的最大长度*/
    if (listen(server_socket, 10) == -1) {
        perror("Error listening on socket");
        exit(EXIT_FAILURE);
    }
    printf("listen success\n");

    while (1) {
        /* 接收一个客户端连接，返回值为成功建立连接的套接字 */
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }
        handle_http_request(client_socket);   
    }

    close(server_socket);
    pthread_exit(NULL);
}

void* https_server(void* args_ptr) {
    struct ThreadArgs* thread_args = (struct ThreadArgs*)args_ptr;
    int server_socket, client_socket;
    /*定义IPV4套接字地址结构体addr*/
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int port_number = thread_args->port;
    SSL_CTX* ssl_context = thread_args->ssl_context;

    /*创建套接字，AF_INET表示IPV4协议族 SOCK_STREAM表示面向连接的字节流（TCP协议），0表示默认使用TCP协议类型*/
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    // 设置addr的端口号为80（需要用htons()函数进行主机序转网络序）
    server_addr.sin_port = htons(port_number);

    /*把创建的socket与指定的地址（IP和端口号）绑定起来，如果失败*/
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }
    printf("bind success\n");

    /*准备监听，使该进程能够接收客户端连接请求，10表示连接请求队列的最大长度*/
    if (listen(server_socket, 10) == -1) {
        perror("Error listening on socket");
        exit(EXIT_FAILURE);
    }
    printf("listen success\n");

    while (1) {
        /* 接收一个客户端连接，返回值为成功建立连接的套接字 */
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }
        handle_https_request(client_socket, ssl_context);   
    }

    close(server_socket);
    pthread_exit(NULL);
}

int main() {
    pthread_t http_thread, https_thread;
    int http_port = HTTP_PORT;
    int https_port = HTTPS_PORT;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX* ssl_context = SSL_CTX_new(TLS_server_method());
    if (!ssl_context) {
        fprintf(stderr, "Error creating SSL context\n");
        return EXIT_FAILURE;
    }

    // 为SSL配置证书和私钥
    if (SSL_CTX_use_certificate_file(ssl_context, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_context, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate or private key file\n");
        SSL_CTX_free(ssl_context);
        return EXIT_FAILURE;
    }

    pthread_create(&http_thread, NULL, http_server, (void*)&http_port);
    struct ThreadArgs https_args = {https_port, ssl_context};
    pthread_create(&https_thread, NULL, https_server, (void*)&https_args);

    pthread_join(http_thread, NULL);
    pthread_join(https_thread, NULL);

    // 清理 SSL 上下文
    SSL_CTX_free(ssl_context);
    EVP_cleanup();
    pthread_exit(NULL);

    return 0;
}
