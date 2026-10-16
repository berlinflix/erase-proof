/* Validate an immutable serialized database without opening filesystem paths. */
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

int ep_sqlite_valid(const unsigned char *data, uint64_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int valid = 0;
    if (!data || size < 100 || size > 256U*1024*1024) return 0;
    if (sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) goto done;
    if (sqlite3_deserialize(db, "main", (unsigned char *)data, size, size, SQLITE_DESERIALIZE_READONLY) != SQLITE_OK) goto done;
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 256*1024*1024);
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check(100)", -1, &statement, NULL) != SQLITE_OK) goto done;
    if (sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_type(statement, 0) == SQLITE_TEXT &&
        strcmp((const char *)sqlite3_column_text(statement, 0), "ok") == 0 && sqlite3_step(statement) == SQLITE_DONE) valid = 1;
done:
    if (statement) sqlite3_finalize(statement);
    if (db) sqlite3_close(db);
    return valid;
}
