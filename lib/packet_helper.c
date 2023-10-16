#include <aos/aos.h>
#include <netutil/checksum.h>
#include <netutil/htons.h>
#include <include/utils.h>

/**
 * Generate an Ethernet packet from a buffer of data.
 *
 * @param addr The address of the buffer containing the data to include in the packet.
 * @param buf  A struct containing information about the buffer, including its valid length.
 * @param pck  A pointer to a pointer to an EthernetPacket struct to hold the resulting packet.
 *             The function allocates memory for the packet and sets the pointer to point to the
 *             allocated memory.
 */
void generate_eth_packet(lvaddr_t addr, size_t len, EthernetPacket **pck){
    *pck = malloc(sizeof(EthernetPacket) - sizeof(EthernetFrame) + len);

    // set the size
    (*pck)->frame_size = len;
    memcpy((void *) &(*pck)->frame, (void *) addr, len);
}

/**
 * Print an ethernet packet to the debug console.
*/
void print_eth_packet(EthernetPacket *pck){
    NET_DEBUG("Eth type: 0x%x - len %lu\n", pck->frame.type, pck->frame_size);
    char *str_to_print = malloc(pck->frame_size*3+1);

    uint8_t *bytes = (uint8_t *) &pck->frame;
    for(size_t i = 0; i < pck->frame_size; i++){
        sprintf(&str_to_print[i*3], "%02x ", bytes[i]);
    }

    str_to_print[pck->frame_size*3] = '\0';
    NET_DEBUG("%s\n", str_to_print);
    free(str_to_print);
}

/**
 * Print an IP packet to the debug console.
*/
void print_ip_packet(IPv4Packet *pck){
    IPv4Header *header = &pck->header;
    char src_ip[16]; char dest_ip[16];
    ip_to_str(src_ip, header->src_ip);
    ip_to_str(dest_ip, header->dest_ip);
    NET_DEBUG("IP Packet\n"
            "Version: %d\n"
            "IHL: %d\n"
            "DSCP: %d\n"
            "ECN: %d\n"
            "Total Length: %d\n"
            "Identification: %d\n"
            "Flags: %d\n"
            "Fragment Offset: %d\n"
            "TTL: %d\n"
            "Protocol: %d\n"
            "Checksum: %d\n"
            "Source IP: %s\n"
            "Destination IP: %s\n",
            header->version,
            header->ihl,
            header->dscp,
            header->ecn,
            header->total_length,
            header->identification,
            header->flags,
            header->fragment_offset,
            header->ttl,
            header->protocol,
            header->header_checksum,
            src_ip,
            dest_ip);
}

/**
 * Print an ARP packet to the debug console.
*/
void print_arp_packet(ARPPacket *pck){
    char src_ip[16]; char dest_ip[16];
    char src_mac[18]; char dest_mac[18];
    ip_to_str(src_ip, pck->src_ip);
    ip_to_str(dest_ip, pck->dest_ip);
    mac_str(src_mac, pck->src_mac);
    mac_str(dest_mac, pck->dest_mac);

    NET_DEBUG("ARP Packet\n"
            "Hardware Type: %d\n"
            "Protocol Type: 0x%04x\n"
            "Hardware Length: %d\n"
            "Protocol Length: %d\n"
            "Operation: %d\n"
            "Source MAC: %s\n"
            "Source IP: %s\n"
            "Destination MAC: %s\n"
            "Destination IP: %s\n",
            pck->htype,
            pck->ptype,
            pck->hlen,
            pck->plen,
            pck->oper,
            src_mac,
            src_ip,
            dest_mac,
            dest_ip);

}

/**
 * Print a MAC address represented as a uint8_t array to the debug console.
*/
void print_mac(mac_addr mac){
    char str_to_print[18];
    mac_str(str_to_print, mac);

    NET_DEBUG("%s\n", str_to_print);
}


/**
 * Convert a MAC address represented as a uint8_t array to a string in
 * colon-separated hexadecimal format.
 *
 * @param mac_str Pointer to a character array to store the resulting string.
 *                The array must have at least 18 bytes of space to hold the
 *                resulting string (17 characters plus a null terminator).
 * @param mac     Pointer to a uint8_t array containing the MAC address to convert.
 */
void mac_str(char *mac_str, mac_addr mac){
    for(size_t i = 0; i < 6; i++){
        sprintf(&mac_str[i*3], "%02x:", mac[i]);
    }
    mac_str[17] = '\0';
}

/**
 * Convert an IPv4 address represented as a uint32_t to a string in
 * dot-separated decimal format.
 *
 * @param ip_str Pointer to a character array to store the resulting string.
 *               The array must have at least 16 bytes of space to hold the
 *               resulting string (15 characters plus a null terminator).
 * @param ip     The IPv4 address in big-endian byte order.
 */
void ip_to_str(char *ip_str, uint32_t ip){
    uint8_t *bytes = (uint8_t *) &ip;
    sprintf(ip_str, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

/**
 * Convert a string in dot-separated decimal format to an IPv4 address
 * represented as a uint32_t.
 * 
 * @param ip_str Pointer to a character array containing the string to convert.
 *              The string must be null-terminated.
 * @return The IPv4 address in big-endian byte order.
 */
uint32_t str_to_ip(char *ip_str){
    uint32_t ip = 0;
    uint8_t *bytes = (uint8_t *) &ip;

    if(sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &bytes[3], &bytes[2], &bytes[1], &bytes[0]) != 4){
        NET_DEBUG("invalid ip string\n");
        return -1;
    }

    return ip;
}

/**
 * Check if a MAC address is the null address (all zeros).
 * 
 * @param mac Pointer to a uint8_t array containing the MAC address to check.
 * @return 1 if the MAC address is the null address, 0 otherwise.
 */
uint8_t is_mac_null(mac_addr mac){
    for(size_t i = 0; i < 6; i++){
        if(mac[i] != 0){
            return 0;
        }
    }
    return 1;
}