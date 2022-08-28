#include "list.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void printl(struct list *linkedList)
{
    while (linkedList != NULL)
    {
        printf("%s\n", linkedList->head->val);
        linkedList->head = linkedList->head->next;
    }
}
void insertToList(struct list *linkedList, char *ipAddress, pthread_mutex_t listLock, pthread_cond_t cv)
{
    struct listelement *newElement = (struct listelement *)malloc(sizeof(struct listelement));
    newElement->val = ipAddress;
    newElement->next = NULL;

    pthread_mutex_lock(&listLock);
    if (linkedList->head == NULL)
    {

        linkedList->head = linkedList->tail = newElement;
        pthread_cond_signal(&cv);

        pthread_mutex_unlock(&listLock);
        return;
    }

    printf("insert to list ip adress - %s - \n", ipAddress);
    struct listelement *temporaryElement = linkedList->tail;
    temporaryElement->next = newElement;
    linkedList->tail = newElement;

    pthread_mutex_unlock(&listLock);

    return;
}

char *pullFromList(struct list *linkedList, pthread_mutex_t listLock, pthread_cond_t cv)
{

    pthread_mutex_lock(&listLock);

    if (linkedList->head == NULL)
        pthread_cond_wait(&cv, &listLock);
    if (linkedList->head != NULL)
    {
        struct listelement *temporaryElement = linkedList->head;
        char *ip = linkedList->head->val;
        linkedList->head = linkedList->head->next;
        free(temporaryElement);
        pthread_mutex_unlock(&listLock);
        printf("ip  %s\n", ip);
        return ip;
    }
    pthread_mutex_unlock(&listLock);
    return NULL;
}
