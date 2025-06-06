// server/server_login.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <signal.h>
#include <sys/wait.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SALT_LEN 17
#define HASH_LEN 65

void handle_sigchld(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int get_user_info(const char *userid, char *salt_out, char *hash_out) {
    sqlite3 *db;
    if (sqlite3_open("../data/users.db", &db) != SQLITE_OK) {
    fprintf(stderr, "❌ 打开数据库失败: %s\n", sqlite3_errmsg(db));
    return 0;
}

    const char *sql = "SELECT salt, hash FROM users WHERE userid = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, userid, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        strcpy(salt_out, (const char *)sqlite3_column_text(stmt, 0));
        strcpy(hash_out, (const char *)sqlite3_column_text(stmt, 1));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

// 去除末尾换行符（支持 \n 和 \r\n）
void strip_newline(char *str) {
    str[strcspn(str, "\r\n")] = '\0';
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    char username[64] = {0};
    char salt[SALT_LEN] = {0};
    char stored_hash[HASH_LEN] = {0};

    // 1. 接收 LOGIN|username\n
    ssize_t len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (len <= 0 || strncmp(buffer, "LOGIN|", 6) != 0) {
        send(client_fd, "FAIL\n", 5, 0);
        close(client_fd);
        exit(0);
    }
    buffer[len] = '\0';
    char *raw = buffer + 6;
    strip_newline(raw);  // 调用已有的 strip_newline 函数
    strncpy(username, raw, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';

    printf("\n===== SM3 哈希验证过程 =====\n");
    printf("[登录] 用户尝试登录: %s\n", username);

    // 2. 从数据库中获取 salt 和 hash
    if (!get_user_info(username, salt, stored_hash)) {
        printf("[登录] 用户 %s 不存在\n", username);
        send(client_fd, "FAIL\n", 5, 0);
        close(client_fd);
        exit(0);
    }

    printf("[登录] 从数据库获取salt: %s\n", salt);
    printf("[登录] 从数据库获取存储的哈希: %s\n", stored_hash);

    // 3. 发送 salt
    char salt_reply[BUFFER_SIZE];
    snprintf(salt_reply, sizeof(salt_reply), "SALT|%s\n", salt);
    ssize_t sent = send(client_fd, salt_reply, strlen(salt_reply), 0);
    if (sent < 0) {
        perror("发送 salt 失败");
        close(client_fd);
        exit(0);
    }
    printf("[登录] 已发送salt给客户端: %s", salt_reply);

    // 4. 接收 HASH|xxx\n
    memset(buffer, 0, sizeof(buffer));
    len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (len <= 0 || strncmp(buffer, "HASH|", 5) != 0) {
        printf("[登录] 接收哈希失败\n");
        send(client_fd, "FAIL\n", 5, 0);
        close(client_fd);
        exit(0);
    }
    buffer[len] = '\0';

    char client_hash[HASH_LEN];
    strncpy(client_hash, buffer + 5, sizeof(client_hash) - 1);
    client_hash[strcspn(client_hash, "\r\n")] = '\0';  // 去除换行

    printf("[登录] 接收到客户端哈希: %s\n", client_hash);

    // 5. 对比哈希值
    printf("[登录] 验证哈希...\n");
    printf("[登录] 客户端哈希: %s\n", client_hash);
    printf("[登录] 数据库哈希: %s\n", stored_hash);
    
    if (strcmp(client_hash, stored_hash) == 0) {
        send(client_fd, "OK\n", 3, 0);
        printf("[登录] 哈希匹配成功 ✅\n");
        printf("[登录] 用户 %s 验证通过\n", username);
    } else {
        send(client_fd, "FAIL\n", 5, 0);
        printf("[登录] 哈希不匹配 ❌\n");
        printf("[登录] 用户 %s 验证失败\n", username);
    }
    printf("===== SM3 哈希验证结束 =====\n\n");

    close(client_fd);
    exit(0);
}


int main() {
    signal(SIGCHLD, handle_sigchld);

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed"); exit(1);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen failed"); exit(1);
    }

    printf("Multi-client login server running on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
        if (client_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd);
        } else {
            close(client_fd);
        }
    }

    return 0;
}


