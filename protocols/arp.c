#include <aos/aos.h>
#include <collections/hash_table.h>
#include "../network.h"

collections_hash_table *arp_table;
extern struct enet_driver_state * st;

#define ARP_REQ 0x1
#define ARP_RPY 0x2

/**
 * Sends an ARP reply to the given MAC and IP addresses.
 *
 * @param mac_dest The MAC address to send the ARP reply to.
 * @param ip_dest The IP address to send the ARP reply to.
 */
static void send_arp_reply(mac_addr mac_dest, uint32_t ip_dest){
    // Allocate memory for the ARP packet
    ARPPacket *pck = malloc(sizeof(ARPPacket));

    // Set the fields of the ARP packet
    pck->htype = 0x1; // Hardware type (Ethernet)
    pck->ptype = 0x800; // Protocol type (IPv4)
    pck->hlen = 6; // Hardware address length (Ethernet)
    pck->plen = 4; // Protocol address length (IPv4)
    pck->oper = ARP_RPY; // ARP operation (reply)
    memcpy(pck->src_mac, st->mac_addr, 6); // Source MAC address
    pck->src_ip = st->my_ip; // Source IP address
    memcpy(pck->dest_mac, mac_dest, 6); // Destination MAC address
    pck->dest_ip = ip_dest; // Destination IP address

    // Send the ARP packet using net_send_packet
    net_send_packet((void *) pck, ETH_TYPE_ARP, sizeof(ARPPacket), pck->dest_mac, pck->dest_ip);

    // Free the memory allocated for the ARP packet
    free((void *)pck);
}

/**
 * Sends an ARP request to resolve the given IP address to a MAC address.
 *
 * @param ip_dest The IP address to resolve to a MAC address.
 */
static void send_arp_request(uint32_t ip_dest){
    // Allocate memory for the ARP packet
    ARPPacket *pck = malloc(sizeof(ARPPacket));

    // Set the fields of the ARP packet
    pck->htype = 0x1; // Hardware type (Ethernet)
    pck->ptype = 0x800; // Protocol type (IPv4)
    pck->hlen = 6; // Hardware address length (Ethernet)
    pck->plen = 4; // Protocol address length (IPv4)
    pck->oper = ARP_REQ; // ARP operation (request)
    memcpy(pck->src_mac, st->mac_addr, 6); // Source MAC address
    pck->src_ip = st->my_ip; // Source IP address
    memset(pck->dest_mac, 0xff, 6); // Destination MAC address (broadcast)
    pck->dest_ip = ip_dest; // Destination IP address

    // Send the ARP packet using net_send_packet
    net_send_packet((void *) pck, ETH_TYPE_ARP, sizeof(ARPPacket), pck->dest_mac, pck->dest_ip);

    // Free the memory allocated for the ARP packet
    free((void *)pck);
}


/**
 * Queries the ARP table for the MAC address of a given IP address.
 * If the MAC address is not found in the table, an ARP request is sent to the network
 * to resolve the IP address to a MAC address.
 *
 * @param ip_dest The IP address to query for the MAC address.
 * @param mac_dest A pointer to a buffer where the MAC address will be stored.
 */
void arp_query(uint32_t ip_dest, mac_addr mac_dest){
    // Try to find the MAC address for the given IP address in the ARP table
    mac_addr *mac;
    thread_mutex_lock_nested(&st->arp_mutex);
    mac = collections_hash_find(arp_table, ip_dest);
    thread_mutex_unlock(&st->arp_mutex);

    // If the MAC address is not found in the ARP table, send an ARP request
    if(mac == NULL){
        send_arp_request(ip_dest);
    } else {
        // If the MAC address is found in the ARP table, copy it to the mac_dest buffer
        memcpy(mac_dest, mac, 6);
    }
}

/**
 * Handle an incoming ARP packet.
 *
 * @param pck A pointer to an ARPPacket struct containing the incoming packet data.
 */
void net_handle_arp(ARPPacket *pck){

    if(pck->hlen != 6 || pck->plen != 4){
        NET_DEBUG("ARP packet has invalid lengths, dropping it\n");
        return;
    }

    mac_addr *mac_to_save;
    uint32_t *ip_to_save;

    //Save the mac anyways, even if the request is not for us
    mac_to_save = pck->src_ip == 0 ? NULL : collections_hash_find(arp_table, pck->src_ip);
    if(mac_to_save == NULL && pck->src_ip != 0){
        mac_to_save = malloc(sizeof(mac_addr));
        ip_to_save = malloc(sizeof(uint32_t));
        
        memcpy(mac_to_save, pck->src_mac, sizeof(mac_addr));
        *ip_to_save = pck->src_ip;

        thread_mutex_lock_nested(&st->arp_mutex);
        collections_hash_insert(arp_table, *ip_to_save, mac_to_save);
        thread_mutex_unlock(&st->arp_mutex);
        char ip_str[16];
        ip_to_str(ip_str, *ip_to_save);

        NET_DEBUG("Saved MAC address for IP: %s\n", ip_str);
        print_mac(*mac_to_save);
    }

    if(pck->dest_ip != st->my_ip){
        NET_DEBUG("ARP packet is not for us, dropping it\n");
        return;
    }

    // print_arp_packet(pck);
    if(pck->oper == ARP_REQ){
        //Send reply
        send_arp_reply(pck->src_mac, pck->src_ip);
    }

    if(pck->oper == ARP_RPY){
        //Received reply
        NET_DEBUG("Received ARP reply\n");
        //Nothing to do - already saved
    }

}

/**
 * Clean up data associated with ARP table.
*/
void arp_clean(void *data){
    free(data);
}

/**
 * Initialize ARP table.
*/
void arp_init(void){
    NET_DEBUG("Initializing ARP\n");
    
    collections_hash_create(&arp_table, arp_clean);

    //Save our own MAC address
    mac_addr *mac = malloc(sizeof(mac_addr));
    memcpy(mac, st->mac_addr, sizeof(mac_addr));

    //Mutex for ARP table
    thread_mutex_init(&st->arp_mutex);

    collections_hash_insert(arp_table, st->my_ip, mac);

    mac_addr *mac2 = collections_hash_find(arp_table, st->my_ip);
    assert(memcmp(mac, mac2, sizeof(mac_addr)) == 0);
}