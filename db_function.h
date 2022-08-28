#include <sqlite3.h>
int creat_or_open_db(char *db_name, sqlite3 *DB);
int creat_table(sqlite3 *DB, char *craet_table);
int query(sqlite3 *DB, char *query);
int select_from_db(sqlite3 *DB, char *select, void callback());
int insert_packet(sqlite3 *DB, const u_char *packet);