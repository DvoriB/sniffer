CC := clang

ifeq ($(DEBUG),1)
	CFLAGS := -Wall -O0 -g
else
	CFLAGS := -Wall -O1 
endif

LDFLAGS := -lpcap -l sqlite3 -pthread  

# -fsanitize=address -Wall

run: sniffex.o hashtable.o db_function.o list.o
	$(CC) -o run sniffex.o  hashtable.o db_function.o  list.o $(LDFLAGS)
	
sniffex.o: sniffex.c
	$(CC) $(CFLAGS) -c sniffex.c $(LDFLAGS)
hashtable.o: hashtable.c hashtable.h
	$(CC) $(CFLAGS) -c hashtable.c $(LDFLAGS) 
db_function.o:db_function.c db_function.h
	$(CC) $(CFLAGS) -c db_function.c $(LDFLAGS)
list.o: list.c list.h
	$(CC) $(CFLAGS) -c list.c $(LDFLAGS)

clear:
	rm  -f *.o run log.txt
	

