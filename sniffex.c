#define APP_NAME "sniffex"
// #define _POSIX_C_SOURCE 199309L
#define APP_DESC "Sniffer example using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
#include <sys/types.h>
#define HAVE_REMOTE
#include <signal.h>
#include "pcap.h"
#include "pthread.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "hashtable.h"
#include <sqlite3.h>
#include "db_function.h"
#include "list.h"

#include <signal.h>
#include <errno.h>
#include <linux/tcp.h>
#include "print_packet.c"
struct list *linkedList; /* global list */

pthread_mutex_t listLock = PTHREAD_MUTEX_INITIALIZER;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
pthread_cond_t cv;
pthread_t thread_list;
#define COUNT 6 // number of attempts
/* default snap length (maximum bytes per packet to capture) */
#include "packet_structs.h"
ht *hash;
ht *hash_block;
pthread_t threads[4];
sigset_t *fSigSet;
sqlite3 *DB;
sqlite3 *DB_BLOCK;
char *messaggeError;
char *password;
static int counter = 0;
char *command;
FILE *logfile;

static int callback(void *data, int argc, char **argv, char **azColName);

void creacte_blocked_packet_table(sqlite3 *DB)
{
	char *blocked_table = "CREATE TABLE BLOCKED("
						  "ip   CHAR(50)  PRIMARY KEY);\0";

	creat_table(DB, blocked_table);
}

void SIGNAL_THREAD()
{
	while (1)
	{
		int nSig;
		sigwait(&fSigSet, &nSig);
		printf("		To display the blocked addresses press 1\n		To remove an address from the black list press 2\n		To print the ip that have the maximum number of packets press 3\n		To print the count of all the ip recived press 4\n		To print the count of all the ip address order by protocol type press 5\n		To get all the packet's data in a log file press 6\n		To stop the program press 7\n");
		int selected;

		scanf("%d", &selected);
		switch (selected)
		{
		case 1:
		{

			select_from_db(DB, "SELECT * FROM BLOCKED", callback);
			printf("--------\n");
			break;
		};
		case 2:
		{
			char *ip = (char *)malloc(sizeof(char) * 20);
			printf("enter ip\n");
			scanf("%s", ip);
			char buffer[1024];
			snprintf(buffer, sizeof(buffer), "DELETE FROM BLOCKED WHERE ip = '%s';", ip);
			select_from_db(DB, buffer, callback);
			sprintf(buffer, " echo %s | sudo -S  iptables -A INPUT -d %s  -j ACCEPT", password, ip);

			system(buffer);
			printf("--------\n");

			break;
		};
		case 3:
		{
			printf("The ip that sent maximum number of packets is:\n");
			select_from_db(DB, "SELECT MAX(count) as items , src_ip as ip FROM (SELECT  src_ip, COUNT(src_ip) as count FROM PACKET GROUP BY src_ip)", callback);
			break;
		};
		case 4:
		{
			select_from_db(DB, "SELECT  src_ip, COUNT(src_ip) as count FROM PACKET GROUP BY src_ip", callback);
			printf("--------\n");

			break;
		}
		case 5:
		{
			printf(" TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Other's : %d   Total : %d\n", tcp, udp, icmp, igmp, others, total);
			printf("--------\n");

			break;
		}
		case 6:
		{
			select_from_db(DB, "SELECT * FROM PACKET", print_packet_log);
			printf("--------\n");

			break;
		}
		case 7:
		{
			exit(0);
			printf("--------\n");

			break;
		}
		}
	}
}

void count_type(u_char protocol)
{
	switch (protocol) // Check the Protocol and do accordingly...
	{
	case 1: // ICMP Protocol
		++icmp;
		break;

	case 2: // IGMP Protocol
		++igmp;
		break;

	case 6: // TCP Protocol
		++tcp;
		break;

	case 17: // UDP Protocol
		++udp;
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
}
void clock_thread()
{

	while (1)
	{
		sleep(20);

		ht_reset(hash);
	}
}

void get_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	struct tcphdr *tcplayer = (struct tcphdr *)(packet + SIZE_ETHERNET + IPHDRLEN);

	count_type(ip->ip_p);
	total++;
	insert_packet(DB, packet);
	if (ht_get(hash_block, inet_ntoa(ip->ip_src)) != 0) // exist in hash
		return;

	if (tcplayer->syn)
	{
		if (!(tcplayer->urg && tcplayer->ack && tcplayer->psh && tcplayer->rst && tcplayer->fin))
		{
			int value = (int)ht_get(hash, inet_ntoa(ip->ip_src)) + 1;
			ht_set(hash, inet_ntoa(ip->ip_src), value);

			if (value == COUNT) // if --somethink
			{
				if (ht_get(hash_block, inet_ntoa(ip->ip_src)) != 0) // exist in hash
					return;
				ht_set(hash_block, inet_ntoa(ip->ip_src), (void *)value);
				insertToList(linkedList, inet_ntoa(ip->ip_src), &listLock, &cv);
			}
			counter++;
		}
	}
}
void my_signal_handler(int signum)
{
	pthread_kill(threads[3], SIGUSR1);
}

int register_signal_handling()
{
	struct sigaction new_action;
	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = my_signal_handler; // Assign the new sinal handler, overwrite default behavior for ctrl+c
	return sigaction(SIGINT, &new_action, NULL);
}

void blockIP(char *ip)
{

	char buffer[1024];
	command = (char *)malloc(sizeof(char) * 1024);
	snprintf(buffer, sizeof(buffer), "INSERT INTO BLOCKED VALUES('%s');", ip);
	query(DB, buffer);
	sprintf(command, " echo %s | sudo -S iptables -I INPUT -d %s -j DROP", password, ip);
	system(command);
	command = "";
}

void threadFunction()
{
	while (1)
	{

		char *ip = pullFromList(linkedList, &listLock, &cv);
		blockIP(ip);
	}
}

void creact_packet_table(sqlite3 *DB)
{
	char *table = "CREATE TABLE PACKET("
				  "ID INTEGER PRIMARY KEY, "
				  "ip_protocol   CHAR(50) NOT NULL, "
				  "src_ip   CHAR(50) NOT NULL, "
				  "dest_ip   CHAR(50) NOT NULL, "
				  "src_port   CHAR(50) NOT NULL, "
				  "dest_port   CHAR(50) NOT NULL );\0";
	creat_table(DB, table);
}
static int callback(void *data, int argc, char **argv, char **azColName)
{
	int i;
	for (i = 0; i < argc; i++)
	{
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}

	printf("\n");
	return 0;
}
static int initHashBlockFromDB(void *data, int argc, char **argv, char **azColName)
{
	int i;

	for (i = 0; i < argc; i++)
	{
		void *value = 0;
		ht_set(hash_block, (char *)argv[i] ? (char *)argv[i] : "", value ? value : "0");
	}

	return 0;
}
void initHashBlock()
{
	select_from_db(DB, "SELECT * FROM BLOCKED", initHashBlockFromDB);
}

int main(int argc, char **argv)
{
	clock_t begin = clock();
	pcap_if_t *alldevs; /* devices list*/
	pcap_if_t *d;
	int i = 0;
	char *dev = NULL;			   /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	pcap_t *handle;				   /* packet capture handle */

	char filter_exp[] = "ip";		 /* filter expression [3] */
	struct bpf_program fp;			 /* compiled filter program (expression) */
	bpf_u_int32 mask;				 /* subnet mask */
	bpf_u_int32 net;				 /* ip */
	int num_packets = 1000000000000; /* number of packets to capture */

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) // if no devices availbale
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}
	printf("Enter the number of the desired device\n");
	int device;
	scanf("%d", &device); // scan for the desired device

	dev = (alldevs + ((device - 1) * sizeof(pcap_if_t)))->name;
	/* We don't need any more the device list. Free it */

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	// command = (char *)malloc(sizeof(char) * 1024);

	// char buffer[100];
	// snprintf(buffer, sizeof(buffer), "echo '%s' | base64;", password);
	// printf("-- %s --\n", buffer);
	// //password = (char *)system(buffer);
	// // printf("%s",password);
	// password[strlen(password)] = '\0';

	// int len_str;
	// len_str =strlen(password);
	// len_str -= 1;
	// printf("Input string is : %s", password);
	// password=base64Encoder(password, len_str);
	// printf("Input string is : %s", password);

	/* now we can set our callback function */
	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
	{
		printf("Unable to create log.txt file.");
	}
	sigemptyset(&fSigSet);
	sigaddset(&fSigSet, SIGUSR1);
	sigaddset(&fSigSet, SIGSEGV);
	register_signal_handling();
	hash = ht_create();
	hash_block = ht_create();
	char *db_name = "db_name.db";
	DB = creat_or_open_db(db_name, DB);
	initHashBlock();
	pthread_cond_init(&cv, NULL);
	linkedList = malloc(sizeof(struct list));
	linkedList->head = NULL;
	linkedList->count = 0;
	password = (char *)malloc(sizeof(char) * 100);
	puts("insert a password ");
	scanf("%s", password);
	creact_packet_table(DB);
	creacte_blocked_packet_table(DB);
	pthread_sigmask(SIG_BLOCK, &fSigSet, NULL);
	pthread_create(&threads[3], NULL, SIGNAL_THREAD, NULL);
	pthread_create(&threads[0], NULL, clock_thread, NULL);
	pthread_create(&threads[1], NULL, threadFunction, NULL);
	pcap_loop(handle, num_packets, get_packet, NULL);
	printf("total entries: %zu\n", hash->capacity);
	/* cleanup */
	ht_destroy(hash);
	pcap_freecode(&fp);
	pcap_close(handle);
	pcap_freealldevs(alldevs);

	while (1)
	{
	};
	return 0;
}
