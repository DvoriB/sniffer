#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
// pthread_mutex_t listLock = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t cv;
struct listelement
{
  char *val;
  struct listelement *next;
};
struct list
{
  struct listelement *head;
  struct listelement *tail;
  int count;
};

void insertToList(struct list *linkedList, char *ipAddress, pthread_mutex_t *listLock, pthread_cond_t* cv);
char *pullFromList(struct list *linkedList, pthread_mutex_t * listLock, pthread_cond_t* cv);
