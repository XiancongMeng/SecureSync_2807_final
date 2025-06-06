#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <fcntl.h>     // 为 open() 提供 O_RDONLY 宏
#include <unistd.h>    // 提供 close() 和 sleep()

#define SALT_LEN 16  // 修改为16字节的salt
#define SM3_DIGEST_LEN 32

// 将字节数组转换为十六进制字符串
void bytes_to_hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; ++i) {
        sprintf(out + i * 2, "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// 检查用户是否已存在
int check_user_exists(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT COUNT(*) FROM users WHERE userid = ?";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return count > 0;  // 返回 1 表示已存在
    }
    
    sqlite3_finalize(stmt);
    return 0;  // 返回 0 表示不存在
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }

    const char *username = argv[1];
    const char *password = argv[2];

    // 打开数据库
    sqlite3 *db;
    if (sqlite3_open("data/users.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Database open error\n");
        return 1;
    }

    // 检查用户是否已存在
    if (check_user_exists(db, username)) {
        printf("User '%s' already exists.\n", username);
        sqlite3_close(db);
        return 1;
    }

    // 生成 16 字节随机 salt
    unsigned char salt[SALT_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        fprintf(stderr, "Salt generation failed\n");
        sqlite3_close(db);
        return 1;
    }

    // 拼接 salt + password
    char input[256];
    memcpy(input, salt, SALT_LEN);
    strncpy(input + SALT_LEN, password, sizeof(input) - SALT_LEN - 1);
    input[sizeof(input) - 1] = '\0';

    // 计算 SM3 哈希
    unsigned char hash[SM3_DIGEST_LEN];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(ctx, input, SALT_LEN + strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    // 转换为十六进制字符串
    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[SM3_DIGEST_LEN * 2 + 1];
    bytes_to_hex(salt, SALT_LEN, salt_hex);
    bytes_to_hex(hash, SM3_DIGEST_LEN, hash_hex);

    // 写入 SQLite 数据库
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO users (userid, salt, hash) VALUES ('%s', '%s', '%s');",
             username, salt_hex, hash_hex);

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL insert error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    printf("User '%s' registered successfully.\n", username);
int fd = open("data/users.db", O_RDONLY);
    if (fd > 0) { fsync(fd); close(fd); sleep(1); }
    sqlite3_close(db);
    return 0;
}

