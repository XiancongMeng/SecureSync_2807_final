// SecureSync/client/upload_file.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define BUFFER_SIZE 4096

// 固定密钥和IV（生产中需使用SM2协商）
unsigned char sm4_key[16] = {
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x00
};

unsigned char sm4_iv[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};

int encrypt_sm4_ctr(const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, sm4_key, sm4_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    char username[64], filepath[256];
    printf("Username: ");
    scanf("%s", username);
    printf("File path to upload: ");
    scanf("%s", filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    struct stat st;
    fstat(fd, &st);
    off_t filesize = st.st_size;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    char header[512];
    snprintf(header, sizeof(header), "%s|%s|%ld", username, filename, filesize);
    send(sock, header, strlen(header), 0);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + 32];  // 加密后长度略大

    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        int encrypted_len = encrypt_sm4_ctr(buffer, bytes_read, encrypted);
        send(sock, encrypted, encrypted_len, 0);
    }

    printf("✅ Encrypted file '%s' uploaded successfully.\n", filename);
    close(fd);
    close(sock);
    return 0;
}

