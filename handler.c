#include <aos/aos.h>
#include <aos/deferred.h>
#include <aos/aos_rpc.h>
#include "network.h"

extern struct enet_driver_state * st;
struct net_lmp *send_list = NULL;
struct thread_mutex send_mutex;

static void net_handle_requests(void *args){
    (void) args;
    //TODO: Read the lmp channel for requests
    // NET_DEBUG("Received request\n");

    char *data;
    size_t len;
    enum net_type type;

    errval_t err = aos_rpc_net_get_request((void **) &data, &len, &type);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to get request from init process");
        return;
    }
    //the pid is the first 4 bytes of the message
    domainid_t pid_req = *(domainid_t *) data;
    // NET_DEBUG("Received %d bytes of type %d from %d\n", len, type, pid_req);

    void *content = data + sizeof(domainid_t);
    len -= sizeof(domainid_t);

    void *ret;
    size_t ret_len;

    switch(type){
        case UDP_REGISTER:
            ret = malloc(sizeof(errval_t));
            ret_len = sizeof(errval_t);
            *(errval_t *) ret = register_port(*(uint16_t *) content, pid_req);
            break;
        case UDP_SEND:
            NET_DEBUG("Received UDP packet to send\n");
            // Expected data: First dest_ip, then dest_port, then src_port, then payload
            uint32_t dest_ip = *(uint32_t *) content;
            uint16_t dest_port = *(uint16_t *) (content + sizeof(uint32_t));
            uint16_t src_port = *(uint16_t *) (content + sizeof(uint32_t) + sizeof(uint16_t));
            uint8_t *payload = (uint8_t *) (content + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t));
            ret = malloc(sizeof(errval_t));
            *(errval_t *) ret = send_udp_packet(src_port, dest_port, payload, len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint16_t), dest_ip);
            ret_len = sizeof(errval_t);
            break;
        case ICMP_PING:
            NET_DEBUG("Received ICMP ping request\n");
            ret = malloc(sizeof(char) * 10);
            ret_len = sizeof(char) * 10;

            icmp_ping(*(uint32_t *) content, 1, (char *) ret);
            break;
        case POLL_REQ:{
            thread_mutex_lock(&send_mutex);
            struct net_lmp *r = send_list;
            struct net_lmp *prev = NULL;

            while(r != NULL){
                if(r->pid == pid_req){
                    break;
                }
                r = r->next;
            }

            if(r != NULL){
                ret = malloc(r->len);
                memcpy(ret, r->data, r->len);
                ret_len = r->len;

                if(prev == NULL){
                    send_list = r->next;
                } else {
                    prev->next = r->next;
                }
                
                free(r);
            } else {
                ret = NULL;
                ret_len = 0;
            }
            thread_mutex_unlock(&send_mutex);
            break;
        }
        default:
            NET_DEBUG("Unknown request type %d\n", type);
            ret = malloc(sizeof(errval_t));
            ret_len = sizeof(errval_t);
            *(errval_t *) ret = NET_ERR_UNKNOWN_REQUEST;
            break;
    }

    free(data);

    err = aos_rpc_net_answer(ret, ret_len, NULL, pid_req, NET_RETURN_VALUE);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to send answer to init process");
        return;
    }

    free(ret);

    err = lmp_chan_register_recv(get_init_rpc()->chan.u.lmp, get_default_waitset(), MKCLOSURE(net_handle_requests, NULL));
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "Failed to register receive handler for init channel");
    }

}

__attribute__((__used__)) static void net_send_message(void){

    // Get the request and update the queue - then unlock.
    thread_mutex_lock(&send_mutex);
    if(send_list == NULL){
        thread_mutex_unlock(&send_mutex);
        return;
    }

    struct net_lmp *r = send_list;
    send_list = send_list->next;
    thread_mutex_unlock(&send_mutex);

    // Deregister the receive handler
    errval_t err = lmp_chan_deregister_recv(get_init_rpc()->chan.u.lmp);
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "Failed to deregister receive handler for init channel");
    }

    // Send the message
    NET_DEBUG("Sending message of %d bytes\n", r->len);
    errval_t *ret;
    err = aos_rpc_net_answer(r->data, r->len, &ret, r->pid, NET_PACKET);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to send message to process from network");
    } else {
        NET_DEBUG("Received return value %d\n", *ret);

        if(*ret == PROC_MGMT_ERR_DOMAIN_NOT_RUNNING){
            NET_DEBUG("Process not running, deleting its services\n");
            // deregister_pid(r->pid); //TODO: implement again
        }

        free(ret);
    }

    free(r);

    // Register the receive handler again
    err = lmp_chan_register_recv(get_init_rpc()->chan.u.lmp, get_default_waitset(), MKCLOSURE(net_handle_requests, NULL));
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "Failed to register receive handler for init channel");
    }

}


void net_add_lmp_req(void *data, size_t len, domainid_t pid){
    struct net_lmp *r = malloc(sizeof(struct net_lmp) + len);

    memcpy(r->data, data, len);
    r->len = len;
    r->pid = pid;
    r->next = NULL;

    thread_mutex_lock(&send_mutex);
    if(send_list == NULL){
        send_list = r;
    }else{
        //Put the request at the end of the list since we want to send in order
        struct net_lmp *tmp = send_list;
        while(tmp->next != NULL){
            tmp = tmp->next;
        }
        tmp->next = r;
    }
    thread_mutex_unlock(&send_mutex);

}

int net_handle_req_init(void *args){
    (void) args;
    
    NET_DEBUG("Initializing network request handler\n");

    // Initialize the send mutex
    thread_mutex_init(&send_mutex);

    // Register the receive handler for the init channel
    // We wait for incoming messages from the init process
    struct lmp_chan *init_chan = get_init_rpc()->chan.u.lmp;
    struct waitset *ws = get_default_waitset();

    errval_t err = lmp_chan_register_recv(init_chan, ws, MKCLOSURE(net_handle_requests, NULL));
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "Failed to register receive handler for init channel");
    }

    while(true){
        // icmp_ping(str_to_ip("192.168.0.70"), 1);
        // barrelfish_usleep(10000000);
        
        // Check for send requests (if the queue contains something then send it)
        // net_send_message();
        // This is prone to race conditions, it needs process binding
        // For now the process asks if we have something to send

        //Check for incoming requests
        event_dispatch_non_block(ws);
        if(err_is_fail(err)){
            NET_DEBUG("Error in event dispatch: %s\n", err_getstring(err));
            continue;
        }
        thread_yield_dispatcher(NULL_CAP);
    }

    return 1;
}