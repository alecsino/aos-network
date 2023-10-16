#ifndef _NETHELPER_H_
#define _NETHELPER_H_

// #define NET_DEBUG_OPTION 1

#if defined(NET_DEBUG_OPTION)
#define NET_DEBUG(x...) debug_printf("[net] " x);
#else
#define NET_DEBUG(fmt, ...) ((void)0)
#endif


/* Packet Helper */
typedef uint8_t mac_addr[6];

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP 0x0800

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t payload[];
} UDPPacket;
typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t zeros;
    uint8_t protocol;
    uint16_t length;
    UDPPacket udp; 
} UDPPesudoHeader;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t rest[4];
    uint8_t payload[];
} ICMPPacket;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    mac_addr src_mac;
    uint32_t src_ip;
    mac_addr dest_mac;
    uint32_t dest_ip;
} ARPPacket;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t dscp:6;
    uint8_t ecn:2;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags:3;
    uint16_t fragment_offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} IPv4Header;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    IPv4Header header;
    uint8_t payload[];
} IPv4Packet;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))){
    mac_addr dest;
    mac_addr src;
    uint16_t type;
    uint8_t payload[];
} EthernetFrame;

typedef struct __attribute__((packed)){
    size_t frame_size;
    EthernetFrame frame;
} EthernetPacket;

void generate_eth_packet(lvaddr_t addr, size_t len, EthernetPacket **pck);
void print_eth_packet(EthernetPacket *pck);
void print_ip_packet(IPv4Packet *pck);
void print_arp_packet(ARPPacket *pck);
void ip_to_str(char *ip_str, uint32_t ip);
void mac_str(char *mac_str, mac_addr mac);
void print_mac(mac_addr mac);
uint32_t str_to_ip(char *ip_str);
uint8_t is_mac_null(mac_addr mac);

#endif