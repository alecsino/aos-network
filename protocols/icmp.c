#include <aos/aos.h>
#include <netutil/checksum.h>
#include <netutil/htons.h>
#include <aos/deferred.h>
#include "../network.h"

#define PING_TIMEOUT 500000 //TODO: check if this is a good value

extern struct enet_driver_state * st;
struct ping_list *p_list = NULL;
uint16_t TX_ID = 0;

static void send_icmp_packet(uint8_t type, uint8_t code, uint8_t *rest, uint8_t *payload, size_t payload_len, uint32_t dest_ip){
    // Build the ICMP packet
    size_t total_len = sizeof(ICMPPacket) + payload_len;
    ICMPPacket *pck = malloc(total_len);
    memset((void *) pck, 0, sizeof(ICMPPacket));
    pck->type = type;
    pck->code = code;
    memcpy(pck->rest, rest, sizeof(pck->rest));
    memcpy(pck->payload, payload, payload_len);
    pck->checksum = ntohs(inet_checksum((void *) pck, total_len));

    // Send the packet
    send_ip_packet((uint8_t *)pck, total_len, 1, dest_ip);

    free((void *) pck);
}

void icmp_ping(uint32_t dest_ip, int count, char *ret){
    uint16_t seq_n = 1;
    const char *payload = "Hello World!";

    uint8_t rest[4];
    while(seq_n <= count){
        // compose the rest of the header - it's TX_ID and seq_n
        TX_ID++;
        
        uint16_t tx_big = htons(TX_ID);
        uint16_t seq_big = htons(seq_n);
        memcpy(rest, &tx_big, 2);
        memcpy(rest + 2, &seq_big, 2);

        struct ping_list *new_ping = malloc(sizeof(struct ping_list));
        memset((void *) new_ping, 0, sizeof(struct ping_list));
        new_ping->tid = TX_ID;
        new_ping->seq_n = seq_n;
        
        thread_mutex_lock(&st->icmp_mutex);
        if (p_list == NULL){
            p_list = new_ping;
            p_list->next = NULL;
        } else {
            new_ping->next = p_list;
            p_list = new_ping;
        }
        new_ping->t_sent =  systime_now();
        thread_mutex_unlock(&st->icmp_mutex);

        send_icmp_packet(8, 0, rest, (uint8_t *) payload, strlen(payload)+1, dest_ip);

        uint8_t try = 0;
        while(try < 10){
            thread_yield();
            barrelfish_usleep(PING_TIMEOUT/10);
            thread_mutex_lock(&st->icmp_mutex);
            if (new_ping->finished){
                thread_mutex_unlock(&st->icmp_mutex);
                break;
            }
            thread_mutex_unlock(&st->icmp_mutex);
            try++;
        }

        thread_mutex_lock(&st->icmp_mutex);

        if(try == 10){
            sprintf(ret, "timeout");
        } else {
            long diff, quot, rem;
            diff = systime_to_us(new_ping->t_received) - systime_to_us(new_ping->t_sent);
            quot = diff / 1000;
            rem = diff % 1000;
            sprintf(ret, "%ld.%03ld ms", quot, rem);
        }

        p_list = p_list->next;
        thread_mutex_unlock(&st->icmp_mutex);
        
        free((void *) new_ping);
        seq_n++;
    }

}

static void icmp_echo_reply(uint16_t id, uint16_t seq_n){
    systime_t end = systime_now();
    
    thread_mutex_lock(&st->icmp_mutex);
    struct ping_list *curr = p_list;
    while(curr != NULL){
        if (curr->tid == id && curr->seq_n == seq_n){
            break;
        }
        curr = curr->next;
    }
    if(curr != NULL) {
        curr->t_received = end;
        curr->finished = 1;
    }
    thread_mutex_unlock(&st->icmp_mutex);

    if (curr == NULL){
        NET_DEBUG("Received ICMP echo reply for unknown ping\n");
    }

    thread_yield();

}

void net_handle_icmp(IPv4Packet *pck){
    // print_icmp_packet(pck);
    ICMPPacket *icmp = (ICMPPacket *)pck->payload;
    size_t payload_len = pck->header.total_length - sizeof(IPv4Header) - sizeof(ICMPPacket);

    switch(icmp->type){
        case 0:
            // Handle ICMP echo reply
            NET_DEBUG("Received ICMP echo reply\n");
            //First 2 bytes are the TX_ID, next 2 are the seq_n
            uint16_t tx_id = ntohs(*(uint16_t *)icmp->rest);
            uint16_t seq_n = ntohs(*(uint16_t *)(icmp->rest + 2));
            icmp_echo_reply(tx_id, seq_n);
            break;
        case 8:
            // Handle ICMP echo request
            NET_DEBUG("Received ICMP echo request\n");
            send_icmp_packet(0, 0, icmp->rest, icmp->payload, payload_len, pck->header.src_ip);
            // Send ICMP echo reply
            // send_icmp_echo_reply(pck->src_ip);
            break;
        default:
            NET_DEBUG("Not implemented ICMP type, dropping packet\n");
            break;
    }
}