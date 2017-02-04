//
// Created by daniel on 1/30/17.
//

#ifndef SDK_DSLINK_C_HTTPSERVER_H
#define SDK_DSLINK_C_HTTPSERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>
#include "libhttp.h"
#include "wq.h"

struct handler_args {
    int fd;
    struct server_globals *globals;
};

struct server_globals {
    wq_t work_queue;
    int num_threads;
    uint16_t server_port;
    char *server_files_directory;
    char *server_proxy_hostname;
    uint16_t server_proxy_port;
    int server_fd;
    void(*request_handler)(struct handler_args*);
    pthread_t thread;
};

void responder_init_server(DSLink *link, DSNode *root, json_t *name, json_t *port, json_t *filedir, json_t *proxy);

#ifdef __cplusplus
}
#endif

#endif //SDK_DSLINK_C_HTTPSERVER_H
