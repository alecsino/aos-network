#ifndef _NETCLIENT_H_
#define _NETCLIENT_H_

#include <include/utils.h>

errval_t client_udp_service(uint16_t port);
errval_t client_udp_listener(IPv4Packet **pck);
errval_t client_send_udp_packet(uint16_t src_port, uint16_t dest_port, uint8_t *payload, size_t payload_len, uint32_t dest_ip);
errval_t client_echo_udp(IPv4Packet *pck);
errval_t client_icmp_ping(uint32_t dest_ip, char **ping_rest);

#endif