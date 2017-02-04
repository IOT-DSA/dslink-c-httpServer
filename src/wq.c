//
// Created by daniel on 1/30/17.
//

#include <stdlib.h>
#include "wq.h"
#include "utlist.h"

/* Initializes a work queue WQ. */
void wq_init(wq_t *wq) {



    wq->size = 0;
    wq->head = NULL;
    pthread_mutex_init(&wq->lock, NULL);
    pthread_cond_init(&wq->not_empty, NULL);
}

/* Remove an item from the WQ. This function should block until there
 * is at least one item on the queue. */
int wq_pop(wq_t *wq) {


    pthread_mutex_lock(&wq->lock);
    while (NULL == wq->head) {
        pthread_cond_wait(&wq->not_empty, &wq->lock);
    }

    wq_item_t *wq_item = wq->head;
    int client_socket_fd = wq->head->client_socket_fd;
    wq->size--;
    DL_DELETE(wq->head, wq->head);

    free(wq_item);

    pthread_mutex_unlock(&wq->lock);

    return client_socket_fd;
}

/* Add ITEM to WQ. */
void wq_push(wq_t *wq, int client_socket_fd) {

    pthread_mutex_lock(&wq->lock);

    wq_item_t *wq_item = calloc(1, sizeof(wq_item_t));
    wq_item->client_socket_fd = client_socket_fd;
    DL_APPEND(wq->head, wq_item);
    wq->size++;

    pthread_mutex_unlock(&wq->lock);
    pthread_cond_signal(&wq->not_empty);
}
