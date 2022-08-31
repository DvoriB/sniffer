

#include "list.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void insertToList(struct list *linkedList, char *ipAddress, pthread_mutex_t *listLock, pthread_cond_t *cv)
{
    struct listelement *newElement = (struct listelement *)malloc(sizeof(struct listelement));
    newElement->val = ipAddress;
    newElement->next = NULL;

    pthread_mutex_lock(listLock);

    if (linkedList->head == NULL)
        linkedList->head = linkedList->tail = newElement;
    else
    {
        struct listelement *temporaryElement = linkedList->tail;
        temporaryElement->next = newElement;
        linkedList->tail = newElement;
    }
    pthread_cond_signal(cv);
    pthread_mutex_unlock(listLock);
    return;
}

char *pullFromList(struct list *linkedList, pthread_mutex_t *listLock, pthread_cond_t *cv)
{

    pthread_mutex_lock(listLock);
    while (linkedList->head == NULL)
        pthread_cond_wait(cv, listLock);

    struct listelement *temporaryElement = linkedList->head;
    char *ip = linkedList->head->val;
    if (linkedList->head == linkedList->tail)
        linkedList->head = linkedList->tail = NULL;
    else
        linkedList->head = linkedList->head->next;
    free(temporaryElement);
    pthread_mutex_unlock(listLock);
    return ip;
}
