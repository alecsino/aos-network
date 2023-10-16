#include <aos/aos.h>
#include <netutil/checksum.h>
#include <netutil/htons.h>
#include "../network.h"

extern struct enet_driver_state * st;

errval_t send_ip_packet(uint8_t *payload, size_t length, uint8_t protocol, uint32_t ip_dest){
    errval_t err = SYS_ERR_OK;
    // Build the IP packet
    size_t total_len = length + sizeof(IPv4Packet);
    IPv4Packet *pck = malloc(total_len);
    memset((void *) pck, 0, sizeof(IPv4Packet));
    pck->header.version = 4;
    pck->header.ihl = 5;
    pck->header.total_length = total_len;
    pck->header.ttl = 64;
    pck->header.protocol = protocol;
    pck->header.src_ip = st->my_ip;
    pck->header.dest_ip = ip_dest;
    pck->header.header_checksum = ntohs(inet_checksum((void *) pck, sizeof(IPv4Header)));
    memcpy(pck->payload, payload, length);

    if(ip_dest == st->my_ip){
        net_handle_ip(pck);
    } else {
        // Send the packet
        err = net_send_packet((void *) pck, ETH_TYPE_IP, total_len, NULL, ip_dest);
    }

    free((void *) pck);
    return err;
}

/**
 * Handle an incoming IPv4 packet.
 *
 * @param pck A pointer to an IPv4Packet struct containing the incoming packet data.
 * 
 * Note: fragmentation is not supported.
 */
void net_handle_ip(IPv4Packet *pck){
    // print_ip_packet(pck);
    
    // if packet is fragmented drop it
    if(pck->header.flags & 0x1 || pck->header.fragment_offset != 0){
        NET_DEBUG("Packet is fragmented, dropping it\n");
        return;
    }

    //check if packet is for us
    if(pck->header.dest_ip != st->my_ip){
        NET_DEBUG("Packet is not for us, dropping it\n");
        return;
    }

    //check if checksum is correct
    uint16_t checksum = pck->header.header_checksum;
    pck->header.header_checksum = 0;
    if(checksum != ntohs(inet_checksum((void *) pck, sizeof(IPv4Header)))){
        NET_DEBUG("Checksum is incorrect, dropping packet\n");
        return;
    }

    switch(pck->header.protocol){
        case 1:
            // Handle ICMP packet
            net_handle_icmp(pck);
            break;
        case 6:
            // Handle TCP packet
            // net_handle_tcp(pck);
            break;
        case 17:
            // Handle UDP packet
            net_handle_udp(pck);
            break;
        default:
            NET_DEBUG("Not implemented protocol, dropping packet\n");
            break;
    }
}
