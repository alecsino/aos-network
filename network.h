#ifndef _NETS_H_
#define _NETS_H_

// #define NET_DEBUG_OPTION 1

#if defined(NET_DEBUG_OPTION)
#define NET_DEBUG(x...) debug_printf("[net] " x);
#else
#define NET_DEBUG(fmt, ...) ((void)0)
#endif

#include "../drivers/enet/enet.h"
#include <include/utils.h>
#include <aos/systime.h>


/* ARP manager */

void arp_init(void);
void arp_clean(void *data);
void net_handle_arp(ARPPacket *pck);
void arp_query(uint32_t ip_dest, mac_addr mac_dest);

/* IP handler */
void net_handle_ip(IPv4Packet *pck);
errval_t send_ip_packet(uint8_t *payload, size_t length, uint8_t protocol, uint32_t ip_dest);

/* ICMP handler */
struct ping_list{
    systime_t t_sent;
    systime_t t_received;
    uint16_t tid;
    uint16_t seq_n;
    uint8_t finished;
    struct ping_list *next;
};

void net_handle_icmp(IPv4Packet *pck);
void icmp_ping(uint32_t dest_ip, int count, char *ret);

/* UDP handler */
struct udp_service{
    uint16_t port;
    domainid_t pid;
    struct udp_service *next;
};

struct speedtest{
    systime_t start;
    systime_t end;
    uint64_t bytes;
};

errval_t send_udp_packet(uint16_t src_port, uint16_t dest_port, uint8_t *payload, size_t payload_len, uint32_t dest_ip);
errval_t register_port(uint16_t port, domainid_t pid);
void deregister_port(uint16_t port);
void net_handle_udp(IPv4Packet *pck);
void udp_init(void);

/* Request handler */

struct net_lmp{
    struct net_lmp *next;
    size_t len;
    domainid_t pid;
    uint8_t data[];
};

int net_handle_req_init(void *args);
void net_add_lmp_req(void *data, size_t len, domainid_t pid);

/* Network */
errval_t net_send_packet(void *packet, uint16_t type, size_t len, mac_addr mac_dest, uint32_t ip);

#endif