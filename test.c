void printm(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// add to data bace
	const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	int value = *((int *)(hash, inet_ntoa(ip->ip_src)));
	printf("%s \n", inet_ntoa(ip->ip_src));
	// const char *ht_set(ht *table, const char *key, void *value);

	value += 1;

	ht_set(hash, inet_ntoa(ip->ip_src), (void *)value);
	if (counter == 0) // if --somethink
	{
		// send ip ,ip is long???
		// insert to the end of list becous i check if ip is exsite
		// linkedListWork(linkedList, (long)inet_ntoa(ip->ip_src));

		insertToList(linkedList, (long)inet_ntoa(ip->ip_src), listLock);

		// char *command = (char *)malloc(sizeof(char) * 100);
		// strcpy(command, "echo 213089345 | sudo -S iptables -I INPUT -d ");
		// strcat(command, inet_ntoa(ip->ip_src));
		// strcat(command, " -j DROP");
		// printf("%s\n", command);
		// system(command);
	}
	counter++;
	// int status = system("echo 213089345 | sudo -S iptables -I INPUT -s 142.251.37.46  -j DROP");
}
void blockIP(long ip){


}

void *threadFunction()
{
	while (1)
	{
		long ip = pullFromList(linkedList, listLock);
		if (ip)
		{
			blockIP(ip);
		}
		else
		{
			// sleep on cv
		}
	}
}