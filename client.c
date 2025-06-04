#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 12345
#define BUFFER_SIZE 1024

SSL *ssl;  // Kết nối SSL toàn cục

void *receive_handler(void *arg) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("\nServer: %s\n", buffer);
        printf("You: ");
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char username[50], password[50];
    int choice;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 1. Khởi tạo OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 2. Tạo socket TCP
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // 3. Tạo SSL object và gắn socket vào SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    printf("Enter commands or messages:\n");

    while (1) {
        printf("Choose option:\n1. Login\n2. Register\nEnter choice: ");
        scanf("%d", &choice);
        getchar(); // clear newline

        if (choice == 1) {
            printf("Enter username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;

            printf("Enter password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = 0;

            snprintf(buffer, sizeof(buffer), "LOGIN %s %s", username, password);
            SSL_write(ssl, buffer, strlen(buffer));

            int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                printf("Disconnected from server.\n");
                break;
            }
            buffer[bytes_read] = '\0';

            if (strncmp(buffer, "LOGIN_SUCCESS", 13) == 0) {
                printf("Login successful. You can start chatting now.\n");

                SSL_write(ssl, "LIST", strlen("LIST"));
                SSL_write(ssl, "/command", strlen("/command"));

                int list_bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                buffer[list_bytes] = '\0';
                printf("%s\n", buffer);

                pthread_t recv_thread;
                pthread_create(&recv_thread, NULL, receive_handler, NULL);

                while (1) {
                    printf("You: ");
                    fgets(buffer, sizeof(buffer), stdin);
                    buffer[strcspn(buffer, "\n")] = '\0';
                    if (strlen(buffer) == 0) continue;
                    SSL_write(ssl, buffer, strlen(buffer));
                }

                break;
            } else {
                printf("Login failed: %s\n", buffer);
            }

        } else if (choice == 2) {
            printf("Enter new username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;

            printf("Enter new password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = 0;

            snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, password);
            SSL_write(ssl, buffer, strlen(buffer));

            int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                printf("Disconnected from server.\n");
                break;
            }
            buffer[bytes_read] = '\0';

            if (strncmp(buffer, "REGISTER_SUCCESS", 16) == 0) {
                printf("Registration successful! You can now login.\n");
            } else {
                printf("Registration failed: %s\n", buffer);
            }

        } else {
            printf("Invalid choice\n");
        }
    }

    // Đóng kết nối SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
