// SecureSync/server/verify_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define SALT_HEX_LEN 17   // 8 字节 -> 16 hex + 1
#define HASH_HEX_LEN 65   // 32 字节 -> 64 hex + 1

// 查询数据库中的 salt 和 hash
int get_user_info(const char *userid, char *salt_out, char *hash_out) {
    sqlite3 *db;
    if (sqlite3_open("data/users.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database\n");
        return 0;
    }

    const char *sql = "SELECT salt, hash FROM users WHERE userid = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, userid, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *salt = sqlite3_column_text(stmt, 0);
        const unsigned char *hash = sqlite3_column_text(stmt, 1);
        strcpy(salt_out, (const char *)salt);
        strcpy(hash_out, (const char *)hash);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 1;
    } else {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <client_hash>\n", argv[0]);
        return 1;
    }

    const char *username = argv[1];
    const char *client_hash = argv[2];

    char stored_salt[SALT_HEX_LEN];
    char stored_hash[HASH_HEX_LEN];

    if (!get_user_info(username, stored_salt, stored_hash)) {
        printf("User '%s' not found.\n", username);
        return 1;
    }

    printf("Retrieved salt: %s\n", stored_salt);
    printf("Expected hash : %s\n", stored_hash);
    printf("Client hash   : %s\n", client_hash);

    if (strcmp(client_hash, stored_hash) == 0) {
        printf("✅ Authentication succeeded.\n");
    } else {
        printf("❌ Authentication failed.\n");
    }

    return 0;
}

