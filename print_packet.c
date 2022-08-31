#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
FILE *logfile;
char *ifBlock[2] = {"TRUE", "FALSE"};
static int print_packet_log(void *data, int argc, char **argv, char **azColName)
{
	int i = 0;

	// iht_get(hash_block, argv[2]) == NULL ? i = 0 : i = 1;

	fprintf(logfile, "=========================packet===============================\n\n");
	// int i;
	// for (i = 0; i < argc; i++)

	fprintf(logfile, "\n");
	fprintf(logfile, "   |-Protocol            : %s \n", argv[1] ? argv[1] : "NULL");
	fprintf(logfile, "   |-Destination Address :  %s \n", argv[2] ? argv[2] : "NULL");
	fprintf(logfile, "   |-Source Address      :  %s \n", argv[3] ? argv[3] : "NULL");
	fprintf(logfile, "   |-Destination Port :  %s \n", argv[4] ? argv[4] : "NULL");
	fprintf(logfile, "   |-Source Port      : %s \n", argv[5] ? argv[5] : "NULL");

	// fprintf(logfile,"%s = %s\n", azColName[1], argv[1] ? argv[1] : "NULL");

	fprintf(logfile, "\n\n========================================================");
	return 0;
}
