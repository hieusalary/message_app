// Chat Server (Refactored with chat history feature)
#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <pthread.h>

#include <arpa/inet.h>

#include <sys/stat.h> 

#include <openssl/ssl.h>

#include <openssl/err.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// ======================= Structs & Globals =======================
typedef struct {
  SSL * ssl;
  int sock;
  char username[50];
  int chatting_with;
}
client_t;

client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// ======================= KHoi tao SSL =======================
SSL_CTX * init_server_ssl_ctx() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  const SSL_METHOD * method = TLS_server_method();
  SSL_CTX * ctx = SSL_CTX_new(method);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

// ======================= Utils: User Database =======================
int check_login(const char * username,
  const char * password) {
  FILE * fp = fopen("users.txt", "r");
  if (!fp) return 0;
  char line[128];
  while (fgets(line, sizeof(line), fp)) {
    char file_user[50], file_pass[50];
    if (sscanf(line, "%[^:]:%s", file_user, file_pass) == 2) {
      if (strcmp(username, file_user) == 0 && strcmp(password, file_pass) == 0) {
        fclose(fp);
        return 1;
      }
    }
  }
  fclose(fp);
  return 0;
}

int username_exists(const char * username) {
  FILE * fp = fopen("users.txt", "r");
  if (!fp) return 0;
  char line[128], file_user[50];
  while (fgets(line, sizeof(line), fp)) {
    if (sscanf(line, "%[^:]", file_user) == 1) {
      if (strcmp(username, file_user) == 0) {
        fclose(fp);
        return 1;
      }
    }
  }
  fclose(fp);
  return 0;
}

int register_user(const char * username,
  const char * password) {
  if (username_exists(username)) return 0;
  FILE * fp = fopen("users.txt", "a");
  if (!fp) return 0;
  fprintf(fp, "%s:%s\n", username, password);
  fclose(fp);
  return 1;
}

// ======================= Utils: Client Management =======================
void add_client(client_t client) {
  pthread_mutex_lock( & clients_mutex);
  if (client_count < MAX_CLIENTS) {
    clients[client_count++] = client;
  }
  pthread_mutex_unlock( & clients_mutex);
}

void remove_client(int sock) {
  pthread_mutex_lock( & clients_mutex);
  for (int i = 0; i < client_count; i++) {
    if (clients[i].sock == sock) {
      for (int j = i; j < client_count - 1; j++) {
        clients[j] = clients[j + 1];
      }
      client_count--;
      break;
    }
  }
  pthread_mutex_unlock( & clients_mutex);
}

void send_online_users_ssl(SSL * ssl) {
  char msg[BUFFER_SIZE];
  pthread_mutex_lock( & clients_mutex);
  snprintf(msg, sizeof(msg), "Online users:\n");
  SSL_write(ssl, msg, strlen(msg));
  for (int i = 0; i < client_count; i++) {
    snprintf(msg, sizeof(msg), "%d. %s\n", i + 1, clients[i].username);
    SSL_write(ssl, msg, strlen(msg));
  }
  pthread_mutex_unlock( & clients_mutex);
}

int find_client_by_index(int index) {
  pthread_mutex_lock( & clients_mutex);
  if (index >= 0 && index < client_count) {
    pthread_mutex_unlock( & clients_mutex);
    return index;
  }
  pthread_mutex_unlock( & clients_mutex);
  return -1;
}

// ======================= Chat History Utils =======================
void ensure_history_folder() {
  struct stat st = {
    0
  };
  if (stat("history", & st) == -1) {
    mkdir("history", 0700); // Tạo folder history với quyền rwx cho owner
  }
}

void get_chat_filename(const char * user1,
  const char * user2, char * filename, size_t size) {
  ensure_history_folder(); // Đảm bảo folder history tồn tại trước khi tạo tên file
  if (strcmp(user1, user2) < 0)
    snprintf(filename, size, "history/%s_%s.txt", user1, user2);
  else
    snprintf(filename, size, "history/%s_%s.txt", user2, user1);
}

void save_chat_message(const char * user1,
  const char * user2,
    const char * message) {
  char filename[256];
  get_chat_filename(user1, user2, filename, sizeof(filename));

  FILE * fp = fopen(filename, "a");
  if (fp) {
    fprintf(fp, "%s\n", message);
    fclose(fp);
  }
}

void send_chat_history_ssl(SSL * ssl,
  const char * user1,
  const char * user2) {
  // Ví dụ: gửi một thông báo tạm thời
  char msg[BUFFER_SIZE];
  snprintf(msg, sizeof(msg), "Chat history between %s and %s is not implemented yet.\n", user1, user2);
  fopen("history", "a"); // Đảm bảo thư mục history tồn tại
  fprintf(stderr, "Sending chat history for %s and %s\n", user1, user2);
  SSL_write(ssl, msg, strlen(msg));

  // Bạn cần bổ sung logic đọc file hoặc dữ liệu chat history rồi gửi
}

// ======================= Command Handlers =======================
void handle_register(SSL * ssl,
  const char * user,
    const char * pass) {
  if (user == NULL || pass == NULL || strlen(user) == 0 || strlen(pass) == 0) {
    SSL_write(ssl, "REGISTER_FAILED: Invalid username or password\n", strlen("REGISTER_FAILED: Invalid username or password\n"));
    return;
  }
  if (register_user(user, pass)) {
    SSL_write(ssl, "REGISTER_SUCCESS\n", strlen("REGISTER_SUCCESS\n"));
  } else {
    SSL_write(ssl, "REGISTER_FAILED: Username already exists or error\n", strlen("REGISTER_FAILED: Username already exists or error\n"));
  }
}

void handle_login(SSL * ssl, int client_sock,
  const char * user,
    const char * pass, int * logged_in, char * username) {
  if (user == NULL || pass == NULL || strlen(user) == 0 || strlen(pass) == 0) {
    SSL_write(ssl, "Login failed: Invalid username or password\n", strlen("Login failed: Invalid username or password\n"));
    return;
  }

  if (check_login(user, pass)) {
    SSL_write(ssl, "LOGIN_SUCCESS\n", strlen("LOGIN_SUCCESS\n"));
    * logged_in = 1;
    printf("Client logged in: %s\n", user);
    strncpy(username, user, 49);
    username[49] = '\0';

    client_t new_client = {0};
    new_client.ssl = ssl;
    new_client.sock = client_sock;
    new_client.chatting_with = -1;
    strncpy(new_client.username, username, sizeof(new_client.username) - 1);
    new_client.username[sizeof(new_client.username) - 1] = '\0';

    add_client(new_client);

    printf("Client connected: socket=%d, username=%s\n", client_sock, username);
    SSL_write(ssl, "Welcome to the chat server!\n", strlen("Welcome to the chat server!\n"));
    send_online_users_ssl(ssl);
    SSL_write(ssl, "Select user to chat (1, 2, ...):\n", strlen("Select user to chat (1, 2, ...):\n"));
  } else {
    SSL_write(ssl, "Login failed\n", strlen("Login failed\n"));
  }
}

// ======================= Client Thread =======================
void * client_handler(void * arg) {
  SSL * ssl = (SSL * ) arg;
  int client_sock = SSL_get_fd(ssl);
  char buffer[BUFFER_SIZE];
  char username[50] = "";
  int logged_in = 0, chatting_with = -1;

  while (1) {
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) break;

    buffer[bytes] = '\0';

    if (!logged_in) {
      char command[16], user[50], pass[50];
      if (sscanf(buffer, "%15s %49s %49s", command, user, pass) != 3) {
        SSL_write(ssl, "Invalid command format\n", 24);
        continue;
      }

      if (strcmp(command, "LOGIN") == 0 && check_login(user, pass)) {
        logged_in = 1;
        strcpy(username, user);

        client_t cli = {
          .ssl = ssl,
          .sock = client_sock,
          .chatting_with = -1
        };
        strcpy(cli.username, user);
        add_client(cli);

        SSL_write(ssl, "LOGIN_SUCCESS\n", 14);
        send_online_users_ssl(ssl);
        SSL_write(ssl, "Select user to chat (1, 2, ...):\n", 34);

      } else if (strcmp(command, "REGISTER") == 0 && register_user(user, pass)) {
        SSL_write(ssl, "REGISTER_SUCCESS\n", 18);
      } else {
        SSL_write(ssl, "Login/Register failed\n", 23);
      }

    } else if (chatting_with == -1) {
      int index = atoi(buffer) - 1;

      pthread_mutex_lock( & clients_mutex);
      if (index >= 0 && index < client_count) {
        chatting_with = index;
        SSL_write(ssl, "=== Chat history ===\n", 22);
        send_chat_history_ssl(ssl, username, clients[index].username);
        SSL_write(ssl, "Now chatting. Type message:\n", 29);
      }
      // else {
      //     SSL_write(ssl, "Invalid selection. Try again:\n", 32);
      //     send_online_users_ssl(ssl);
      // }
      pthread_mutex_unlock( & clients_mutex);

    } else {
      if (strncmp(buffer, "/exit", 5) == 0) {
        chatting_with = -1;
        SSL_write(ssl, "Exited chat. Select user to chat (1, 2, ...):\n", 47);
        send_online_users_ssl(ssl);

      } else if (strncmp(buffer, "/list", 5) == 0) {
        send_online_users_ssl(ssl);

      } else if (strncmp(buffer, "/command", 8) == 0) {
        const char * cmd =
          "Available commands:\n"
        "/command        - Show this help message\n"
        "/list           - Show list of online users\n"
        "/switch <n>     - Switch chat to user n\n"
        "/exit           - Exit chat\n";
        SSL_write(ssl, cmd, strlen(cmd));

      } else if (strncmp(buffer, "/switch", 7) == 0) {
        int new_index = atoi(buffer + 8) - 1;

        pthread_mutex_lock( & clients_mutex);
        if (new_index >= 0 && new_index < client_count) {
          chatting_with = new_index;
          SSL_write(ssl, "=== Chat history ===\n", 22);
          send_chat_history_ssl(ssl, username, clients[new_index].username);
          SSL_write(ssl, "Switched chat. Type message:\n", 30);
        } else {
          SSL_write(ssl, "Invalid user index.\n", 21);
        }
        pthread_mutex_unlock( & clients_mutex);

      } else {
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "[%s]: %s", username, buffer);

        pthread_mutex_lock( & clients_mutex);
        if (chatting_with >= 0 && chatting_with < client_count) {
          SSL * target_ssl = clients[chatting_with].ssl;
          if (target_ssl != NULL) {
            SSL_write(target_ssl, msg, strlen(msg));
            save_chat_message(username, clients[chatting_with].username, msg);
          }
        }
        pthread_mutex_unlock( & clients_mutex);
      }
    }
  }

  remove_client(client_sock);
  printf("❌ Client disconnected: %s\n", username);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(client_sock);
  pthread_exit(NULL);
}

// ======================= Main =======================
int main() {
  int server_sock;
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  SSL_CTX * ctx = init_server_ssl_ctx();

  server_sock = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, & (int) {
    1
  }, sizeof(int));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  bind(server_sock, (struct sockaddr * ) & addr, sizeof(addr));
  listen(server_sock, 10);

  printf("Secure chat server listening on port %d...\n", PORT);

  while (1) {
    int client = accept(server_sock, (struct sockaddr * ) & addr, & len);
    SSL * ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(client);
      SSL_free(ssl);
      continue;
    }

    pthread_t tid;
    pthread_create( & tid, NULL, client_handler, ssl);
    pthread_detach(tid);
  }

  close(server_sock);
  SSL_CTX_free(ctx);
  return 0;
}