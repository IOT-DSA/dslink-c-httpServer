//
// Created by daniel on 1/30/17.
//
#define LOG_TAG "httpserver"

#include <dslink/log.h>
#include "httpserver.h"
#include "actions.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>




struct redirect_args {
    int to;
    int from;
    pthread_mutex_t *lock;
    pthread_cond_t *done;
};



int send_file(int fd, char *path);
int send_dir(int fd, char *path);
void send_fail(int fd, int code);

void be_a_thread(struct server_globals *globals);

void handle_redirect(struct redirect_args *args);

/*
 * Reads an HTTP request from stream (fd), and writes an HTTP response
 * containing:
 *
 *   1) If user requested an existing file, respond with the file
 *   2) If user requested a directory and index.html exists in the directory,
 *      send the index.html file.
 *   3) If user requested a directory and index.html doesn't exist, send a list
 *      of files in the directory with links to each.
 *   4) Send a 404 Not Found response.
 */
void handle_files_request(struct handler_args *args) {

    struct http_request *request = http_request_parse(args->fd);
    if (!request) {
        return;
    }

    char *method = request->method;
    if (0 != strcmp("GET", method)) {
        send_fail(args->fd, 405);
        return;
    }
    char *path;
    size_t filedirlen = strlen(args->globals->server_files_directory);
    path = calloc(filedirlen + strlen(request->path) + 1, sizeof(char));
    if (!path) {
        send_fail(args->fd, 418);
        return;
    }

    strncpy(path, args->globals->server_files_directory, filedirlen);
    strcat(path, request->path);

    //printf("%s\n", path);

    struct stat *statbuf = malloc(sizeof(struct stat));
    if (stat(path, statbuf) < 0) {
        free(path);
        send_fail(args->fd, 404);
        return;
    }

    if (S_ISREG(statbuf->st_mode)) {
        if (send_file(args->fd, path) < 0) {
            send_fail(args->fd, 404);
        }
    }
    else if (S_ISDIR(statbuf->st_mode)) {
        char* ipath;
        if ('/' == path[strlen(path) - 1]) {
            ipath = calloc(strlen(path) + 11, sizeof(char));
            strncpy(ipath, path, strlen(path));
            strcat(ipath, "index.html");
        }
        else {
            ipath = calloc(strlen(path) + 12, sizeof(char));
            strncpy(ipath, path, strlen(path));
            strcat(ipath, "/index.html");
        }

        if (send_file(args->fd, ipath) < 0) {
            if (send_dir(args->fd, path) < 0) {
                send_fail(args->fd, 404);
            }
        }
        free(ipath);
    }
    else {
        send_fail(args->fd, 404);
    }
    free(statbuf);
    free(path);
    free(request);
}

int send_file(int fd, char *path) {
    //printf("%s\n", path);
    char * buf = 0;
    size_t filelen;
    FILE * f = fopen(path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        filelen = ftell(f);
        buf = malloc(filelen);
        fseek(f, 0, SEEK_SET);
        if (buf) {
            fread(buf, 1, filelen, f);
        }
        fclose(f);

        char lenstr[25];
        sprintf(lenstr, "%zd", filelen);

        http_start_response(fd, 200);
        http_send_header(fd, "Content-Type", http_get_mime_type(path));
        http_send_header(fd, "Content-Length", lenstr);
        http_end_headers(fd);
        http_send_data(fd, buf, filelen);
        return 1;
    }
    else {
        return -1;
    }
}

int send_dir(int fd, char *path) {

    DIR *dirp = opendir(path);

    if (dirp) {
        http_start_response(fd, 200);
        http_send_header(fd, "Content-Type", "text/html");
        http_end_headers(fd);
        //http_send_string(fd, "<a href=\".. / \">Parent directory</a>\n");
        struct dirent *dp;
        while ((dp = readdir(dirp)) != NULL) {
            http_send_string(fd, "<a href=\"");
            http_send_string(fd, dp->d_name);
            http_send_string(fd, "\">");
            http_send_string(fd, dp->d_name);
            http_send_string(fd, "</a><br>");
        }
        closedir(dirp);
        return 1;
    }
    else {
        closedir(dirp);
        return -1;
    }
}

void send_fail(int fd, int code) {
    http_start_response(fd, code);
    //printf("sent errcode\n");
    http_end_headers(fd);
}


/*
 * Opens a connection to the proxy target (hostname=server_proxy_hostname and
 * port=server_proxy_port) and relays traffic to/from the stream fd and the
 * proxy target. HTTP requests from the client (fd) should be sent to the
 * proxy target, and HTTP responses from the proxy target should be sent to
 * the client (fd).
 *
 *   +--------+     +------------+     +--------------+
 *   | client | <-> | httpserver | <-> | proxy target |
 *   +--------+     +------------+     +--------------+
 */

void handle_proxy_request(struct handler_args *args) {


    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    struct addrinfo *results;
    struct sockaddr_in *addr;
    int retcode = getaddrinfo(args->globals->server_proxy_hostname, "http", &hints, &results);
    if (0 != retcode) {
        send_fail(args->fd, 404);
        return;
    }
    addr = (struct sockaddr_in *) results->ai_addr;

    int sock = socket(PF_INET, SOCK_STREAM, 0);

    addr->sin_family = AF_INET;
    addr->sin_port = htons(args->globals->server_proxy_port);

    connect(sock, (struct sockaddr*)addr, sizeof(*addr));

    pthread_cond_t done;
    pthread_mutex_t lock;
    pthread_mutex_init(&lock, NULL);
    pthread_cond_init(&done, NULL);

    struct redirect_args upargs, dnargs;
    upargs.from = args->fd;
    upargs.to = sock;
    upargs.lock = &lock;
    upargs.done = &done;
    dnargs.from = sock;
    dnargs.to = args->fd;
    dnargs.lock = &lock;
    dnargs.done = &done;

    pthread_t thread_up;
    pthread_t thread_dn;
    pthread_create(&thread_dn, NULL, (void * (*)(void *))&handle_redirect, &dnargs);
    pthread_create(&thread_up, NULL, (void * (*)(void *))&handle_redirect, &upargs);

    pthread_mutex_lock(&lock);
    pthread_cond_wait(&done, &lock);

    pthread_cancel(thread_up);
    pthread_cancel(thread_dn);

}

void handle_redirect(struct redirect_args *args) {
    char buff[1024];
    size_t n;
    while ((n = read(args->from, buff, 1023)) > 0) {
        buff[n] = 0;
        write(args->to, buff, n);
    }
    pthread_cond_signal(args->done);
}


/*
 * Opens a TCP stream socket on all interfaces with port number PORTNO. Saves
 * the fd number of the server socket in *socket_number. For each accepted
 * connection, calls request_handler with the accepted fd number.
 */
void serve_forever(struct server_globals *g) {

    //void (*request_handler)(struct handler_args*) = g->request_handler;

    struct sockaddr_in server_address, client_address;
    size_t client_address_length = sizeof(client_address);
    int client_socket_number;

    g->server_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (g->server_fd == -1) {
        log_err("Failed to create a new socket");
        exit(errno);
    }

    int socket_option = 1;
    if (setsockopt(g->server_fd, SOL_SOCKET, SO_REUSEADDR, &socket_option,
                   sizeof(socket_option)) == -1) {
        log_err("Failed to set socket options");
        exit(errno);
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(g->server_port);

    if (bind(g->server_fd, (struct sockaddr *) &server_address,
             sizeof(server_address)) == -1) {
        log_err("Failed to bind on socket");
        exit(errno);
    }

    if (listen(g->server_fd, 1024) == -1) {
        log_err("Failed to listen on socket");
        exit(errno);
    }

    log_info("Listening on port %d...\n", g->server_port);

    //wq_init(&(g->work_queue));

    int i;
    for (i = 0; i < g->num_threads; i++) {
        pthread_t thread;
        pthread_create(&thread, NULL, (void * (*)(void *)) &be_a_thread, g);
    }

    while (1) {
        client_socket_number = accept(g->server_fd,
                                      (struct sockaddr *) &client_address,
                                      (socklen_t *) &client_address_length);
        if (client_socket_number < 0) {
            log_err("Error accepting socket");
            continue;
        }

        log_info("Accepted connection from %s on port %d\n",
               inet_ntoa(client_address.sin_addr),
               client_address.sin_port);

        wq_push(&g->work_queue, client_socket_number);
    }

    shutdown(g->server_fd, SHUT_RDWR);
    close(g->server_fd);
}

void be_a_thread(struct server_globals *globals) {
    int fd;
    struct handler_args hargs;
    hargs.globals = globals;
    while (1) {
        fd = wq_pop(&globals->work_queue);
        hargs.fd = fd;
        globals->request_handler(&hargs);
        close(fd);
    }
}


//int server_fd;
void signal_callback_handler(int signum) {
    log_info("Caught signal %d: %s\n", signum, strsignal(signum));
    //log_info("Closing socket %d\n", server_fd);
    //if (close(server_fd) < 0) log_err("Failed to close server_fd (ignoring)\n");
    exit(0);
}

void globals_init(struct server_globals *globals) {
    globals->num_threads = 1;
    globals->server_files_directory = NULL;
    globals->server_port = 8000;
    globals->server_proxy_hostname = NULL;
    globals->server_proxy_port = 80;
    wq_init(&globals->work_queue);
}

void responder_init_server(DSLink *link, DSNode *root, json_t *name, json_t *port, json_t *filedir, json_t *proxy) {
    DSNode *serv = dslink_node_create(root, json_string_value(name), "node");
    if (!serv) {
        log_warn("Failed to create the server node\n");
        return;
    }

    if (dslink_node_add_child(link, serv) != 0) {
        log_warn("Failed to add the server node to the root\n");
        dslink_node_tree_free(link, serv);
        return;
    }

    make_server_actions(link, serv);


    signal(SIGINT, signal_callback_handler);

    struct server_globals *globals = calloc(1, sizeof(struct server_globals));
    if (!globals) {
        log_warn("Failed to create server globals struct\n");
        dslink_node_tree_free(link, serv);
        return;
    }
    globals_init(globals);

    dslink_node_set_meta_new(link, serv, "$globals", json_integer((long long) globals));

    if (filedir) {
        globals->request_handler = handle_files_request;
        //free(globals->server_files_directory);
        globals->server_files_directory = (char *) json_string_value(filedir);
    } else if (proxy) {
        globals->request_handler = handle_proxy_request;
        char *proxy_target = (char *) json_string_value(proxy);
        char *colon_pointer = strchr(proxy_target, ':');
        if (colon_pointer != NULL) {
            *colon_pointer = '\0';
            globals->server_proxy_hostname = proxy_target;
            globals->server_proxy_port = atoi(colon_pointer + 1);
        } else {
            globals->server_proxy_hostname = proxy_target;
            globals->server_proxy_port = 80;
        }
    }

    if (port) {
        globals->server_port = json_integer_value(port);
    }

    if (globals->server_files_directory == NULL && globals->server_proxy_hostname == NULL) {
        log_warn("Must specify a file directory or proxy hostname");
        dslink_node_tree_free(link, serv);
        return;
    }


    pthread_create(&globals->thread, NULL, (void * (*)(void *)) &serve_forever, globals);
    //serve_forever(&args);
}