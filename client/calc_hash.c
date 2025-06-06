// SecureSync/client/calc_hash.c
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define SM3_DIGEST_LENGTH 32

// 将字节数组转换为十六进制字符串
void bytes_to_hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; ++i)
        sprintf(out + i * 2, "%02x", in[i]);
    out[len * 2] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <salt_hex> <password>\n", argv[0]);
        return 1;
    }

    const char *salt_hex = argv[1];
    const char *password = argv[2];

    // 将 hex salt 转为二进制
    unsigned char salt[8];
    for (int i = 0; i < 8; ++i) {
        sscanf(salt_hex + 2 * i, "%2hhx", &salt[i]);
    }

    // 拼接 salt + password
    char input[256];
    memcpy(input, salt, 8);
    strncpy(input + 8, password, sizeof(input) - 9);
    input[sizeof(input) - 1] = '\0';

    // 计算 SM3 hash
    unsigned char hash[SM3_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(ctx, input, 8 + strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    // 输出 hash 为 hex 字符串
    char hash_hex[SM3_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(hash, SM3_DIGEST_LENGTH, hash_hex);
    printf("Client-side hash: %s\n", hash_hex);

    return 0;
}

