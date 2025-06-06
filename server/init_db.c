// SecureSync/server/init_db.c
#include <stdio.h>
#include <sqlite3.h>

int main() {
    sqlite3 *db;
    char *err_msg = 0;

    int rc = sqlite3_open("data/users.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    const char *sql_users =
        "CREATE TABLE IF NOT EXISTS users ("
        "userid TEXT PRIMARY KEY,"
        "salt TEXT NOT NULL,"
        "hash TEXT NOT NULL);";

    const char *sql_logs =
        "CREATE TABLE IF NOT EXISTS logs ("
        "timestamp TEXT NOT NULL,"
        "userid TEXT NOT NULL,"
        "operation TEXT NOT NULL);";

    rc = sqlite3_exec(db, sql_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (users): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    rc = sqlite3_exec(db, sql_logs, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (logs): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    printf("Database initialized successfully.\n");
    sqlite3_close(db);
    return 0;
}

