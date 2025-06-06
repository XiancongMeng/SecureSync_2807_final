// SecureSync/client/client_login.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define SALT_LEN 8
#define HASH_LEN 32

void bytes_to_hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; ++i)
        sprintf(out + i * 2, "%02x", in[i]);
    out[len * 2] = '\0';
}

void hex_to_bytes(const char *in, unsigned char *out, int len) {
    for (int i = 0; i < len; ++i)
        sscanf(in + 2 * i, "%2hhx", &out[i]);
}

int main() {
    char username[64], password[64];
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return 1;
    }

    // 1. 发送 LOGIN|username
    char send_buf[BUFFER_SIZE];
    snprintf(send_buf, sizeof(send_buf), "LOGIN|%s", username);
    send(sock, send_buf, strlen(send_buf), 0);

    // 2. 接收 SALT|xxxx
    char recv_buf[BUFFER_SIZE] = {0};
    recv(sock, recv_buf, sizeof(recv_buf), 0);
    if (strncmp(recv_buf, "SALT|", 5) != 0) {
        printf("Login failed: %s\n", recv_buf);
        close(sock);
        return 1;
    }
    char salt_hex[17];
    strcpy(salt_hex, recv_buf + 5);
    printf("Received salt: %s\n", salt_hex);

    // 3. 计算 SM3(salt + password)
    unsigned char salt[SALT_LEN];
    hex_to_bytes(salt_hex, salt, SALT_LEN);

    char input[256];
    memcpy(input, salt, SALT_LEN);
    strcpy(input + SALT_LEN, password);

    unsigned char hash[HASH_LEN];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(ctx, input, SALT_LEN + strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    char hash_hex[HASH_LEN * 2 + 1];
    bytes_to_hex(hash, HASH_LEN, hash_hex);

    // 4. 发送 HASH|xxx
    snprintf(send_buf, sizeof(send_buf), "HASH|%s", hash_hex);
    send(sock, send_buf, strlen(send_buf), 0);

    // 5. 接收 OK / FAIL
    memset(recv_buf, 0, sizeof(recv_buf));
    recv(sock, recv_buf, sizeof(recv_buf), 0);
    if (strcmp(recv_buf, "OK") == 0) {
        printf("✅ Login success!\n");
    } else {
        printf("❌ Login failed.\n");
    }

    close(sock);
    return 0;
}

