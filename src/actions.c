//
// Created by daniel on 2/1/17.
//
#define LOG_TAG "httpserver"

#include <dslink/log.h>
#include <unistd.h>
#include "actions.h"
#include "httpserver.h"

static
void invoke_delete(DSLink *link, DSNode *node, json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) rid;
    (void) params;
    (void) stream_ref;

    DSNode *serv = node->parent;
    struct server_globals *g = (struct server_globals *) json_integer_value(dslink_node_get_meta(serv, "$globals"));
    if (g) {
        pthread_cancel(g->thread);
        shutdown(g->server_fd, SHUT_RDWR);
        close(g->server_fd);
        free(g);
    }
    dslink_node_tree_free(link, serv);


}

void make_server_actions(DSLink *link, DSNode *serv) {
    DSNode *deleteNode = dslink_node_create(serv, "delete", "node");
    if (!deleteNode) {
        log_warn("Failed to create delete action node\n");
        return;
    }

    deleteNode->on_invocation = invoke_delete;
    dslink_node_set_meta(link, deleteNode, "$name", json_string("Delete"));
    dslink_node_set_meta(link, deleteNode, "$invokable", json_string("read"));

    if (dslink_node_add_child(link, deleteNode) != 0) {
        log_warn("Failed to add delete action to the root node\n");
        dslink_node_tree_free(link, deleteNode);
        return;
    }
}