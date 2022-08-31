#include <stdio.h>
#include "packet_structs.h"
#include <sys/types.h>
#define HAVE_REMOTE
#include "pcap.h"
#include "pthread.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sqlite3.h>

sqlite3 *creat_or_open_db(char *db_name, sqlite3 *DB)
{
    int exit = sqlite3_open(db_name, &DB);
    if (exit)
    {
        return NULL;
    }
    return DB;
}

int creat_table(sqlite3 *DB, char *craet_table)
{
    char *messaggeError;
    int exit = sqlite3_exec(DB, craet_table, NULL, 0, &messaggeError);
    if (exit != SQLITE_OK)
    {
        sqlite3_free(messaggeError);
    }

    return (0);
}

int query(sqlite3 *DB, char *query)
{
    char *messaggeError;
    int exit = sqlite3_exec(DB, query, NULL, 0, &messaggeError);
    if (exit != SQLITE_OK)
    {
        sqlite3_free(messaggeError);
        return -1;
    }

    return 0;
}

int insert_packet(sqlite3 *DB, const u_char *packet)
{
    struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(packet);
    struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    struct sniff_tcp *tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);

    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "INSERT INTO PACKET VALUES(NULL, '%d' , '%s' , '%s' , '%d' , '%d');", ip->ip_p, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), (tcp->th_sport), (tcp->th_dport));
    query(DB, buffer);
}

// for callback you need to send the name of the function
int select_from_db(sqlite3 *DB, char *select, void callback())
{
    int rc = sqlite3_exec(DB, select, callback, NULL, NULL);

    if (rc != SQLITE_OK)
    {
        return -1;
    }

    return 0;
}
