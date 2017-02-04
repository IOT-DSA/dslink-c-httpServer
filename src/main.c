#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/storage/storage.h>
#include <dslink/node.h>
#include <dslink/ws.h>

#include "httpserver.h"


static
void invoke_make_server(DSLink *link, DSNode *node,
                      json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) rid;
    (void) stream_ref;

    json_t *name = json_incref(json_object_get(params, "name"));
    json_t *port = json_incref(json_object_get(params, "port"));
    json_t *filedir = json_incref(json_object_get(params, "file directory"));
    json_t *proxy = json_incref(json_object_get(params, "proxy"));

    responder_init_server(link, node->parent, name, port, filedir, proxy);

}


// Called to initialize your node structure.
void init(DSLink *link) {
    json_t *messageValue = dslink_json_get_config(link, "message");
    if (messageValue) {
        log_info("Message = %s\n", json_string_value(messageValue));
    }

    DSNode *superRoot = link->responder->super_root;


    {
        DSNode *makeServerNode = dslink_node_create(superRoot, "makeServer", "node");
        if (!makeServerNode) {
            log_warn("Failed to create make server action node\n");
            return;
        }

        makeServerNode->on_invocation = invoke_make_server;
        dslink_node_set_meta(link, makeServerNode, "$name", json_string("Make Server"));
        dslink_node_set_meta(link, makeServerNode, "$invokable", json_string("read"));


        json_t *params = json_array();
        json_t *message_param = json_object();
        json_object_set_new(message_param, "name", json_string("name"));
        json_object_set_new(message_param, "type", json_string("string"));
        json_array_append_new(params, message_param);

        message_param = json_object();
        json_object_set_new(message_param, "name", json_string("port"));
        json_object_set_new(message_param, "type", json_string("number"));
        json_array_append_new(params, message_param);

        message_param = json_object();
        json_object_set_new(message_param, "name", json_string("file directory"));
        json_object_set_new(message_param, "type", json_string("string"));
        json_array_append_new(params, message_param);


        //dslink_node_set_meta(link, echoNode, "$columns", columns);
        dslink_node_set_meta(link, makeServerNode, "$params", params);

        if (dslink_node_add_child(link, makeServerNode) != 0) {
            log_warn("Failed to add make server action to the root node\n");
            dslink_node_tree_free(link, makeServerNode);
            return;
        }
    }

    {
        DSNode *makeProxyNode = dslink_node_create(superRoot, "makeProxyServer", "node");
        if (!makeProxyNode) {
            log_warn("Failed to create make proxy server action node\n");
            return;
        }

        makeProxyNode->on_invocation = invoke_make_server;
        dslink_node_set_meta(link, makeProxyNode, "$name", json_string("Make Proxy Server"));
        dslink_node_set_meta(link, makeProxyNode, "$invokable", json_string("read"));


        json_t *params = json_array();
        json_t *message_param = json_object();
        json_object_set_new(message_param, "name", json_string("name"));
        json_object_set_new(message_param, "type", json_string("string"));
        json_array_append_new(params, message_param);

        message_param = json_object();
        json_object_set_new(message_param, "name", json_string("port"));
        json_object_set_new(message_param, "type", json_string("number"));
        json_array_append_new(params, message_param);

        message_param = json_object();
        json_object_set_new(message_param, "name", json_string("proxy"));
        json_object_set_new(message_param, "type", json_string("string"));
        json_array_append_new(params, message_param);


        //dslink_node_set_meta(link, echoNode, "$columns", columns);
        dslink_node_set_meta(link, makeProxyNode, "$params", params);

        if (dslink_node_add_child(link, makeProxyNode) != 0) {
            log_warn("Failed to add make proxy action to the root node\n");
            dslink_node_tree_free(link, makeProxyNode);
            return;
        }
    }

    // add link data
    json_t * linkData = json_object();
    json_object_set_nocheck(linkData, "test", json_true());
    link->link_data = linkData;

    log_info("Initialized!\n");
}

// Called when the DSLink is connected.
void connected(DSLink *link) {
    (void) link;
    log_info("Connected!\n");
}

// Called when the DSLink is disconnected.
// If this was not initiated by dslink_close,
// then a reconnection attempt is made.
void disconnected(DSLink *link) {
    (void) link;
    log_info("Disconnected!\n");
}

// The main function.
int main(int argc, char **argv) {
    DSLinkCallbacks cbs = { // Create our callback struct.
        init, // init_cb
        connected, //on_connected_cb
        disconnected, // on_disconnected_cb
        NULL // on_requester_ready_cb
    };

    // Initializes a DSLink and handles reconnection.
    // Pass command line arguments, our dsId,
    // are we a requester?, are we a responder?, and a reference to our callbacks.
    return dslink_init(argc, argv, "HttpServer", 0, 1, &cbs);
}
