//
// Created by daniel on 1/30/17.
//

#ifndef SDK_DSLINK_C_WQ_H
#define SDK_DSLINK_C_WQ_H

#include <pthread.h>

/* WQ defines a work queue which will be used to store accepted client sockets
 * waiting to be served. */

typedef struct wq_item {
    int client_socket_fd; // Client socket to be served.
    struct wq_item *next;
    struct wq_item *prev;
} wq_item_t;

typedef struct wq {
    int size;
    wq_item_t *head;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
} wq_t;

void wq_init(wq_t *wq);
void wq_push(wq_t *wq, int client_socket_fd);
int wq_pop(wq_t *wq);

#endif //SDK_DSLINK_C_WQ_H
