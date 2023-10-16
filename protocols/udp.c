#include <aos/aos.h>
#include <netutil/checksum.h>
#include <netutil/htons.h>
#include <aos/deferred.h>
#include <collections/hash_table.h>
#include <sys/time.h>
#include <aos/aos_rpc.h>
#include "../network.h"

#define N_SERVICES 3
#define ECHO_PORT 7
#define SPEEDTEST_PORT 8008
#define UPLOAD_SPEEDTEST_PORT 8009

const uint16_t services[] = { ECHO_PORT,  SPEEDTEST_PORT, UPLOAD_SPEEDTEST_PORT };

extern struct enet_driver_state * st;
collections_hash_table *udp_services;
struct thread_mutex udp_services_mutex;
struct speedtest current_speedtest;

/**
 * Calculates the UDP checksum for the given UDP packet, using the specified source and destination IP addresses.
 * The checksum is calculated over a pseudo-header that includes the source and destination IP addresses, the protocol
 * number (17 for UDP), and the UDP length, followed by the UDP packet itself.
 *
 * @param udp The UDP packet to calculate the checksum for.
 * @param src_ip The source IP address to use in the pseudo-header.
 * @param dest_ip The destination IP address to use in the pseudo-header.
 * @return The calculated checksum value.
 */
static uint16_t udp_checksum(UDPPacket *udp, uint32_t src_ip, uint32_t dest_ip){

    size_t len = sizeof(UDPPesudoHeader) + udp->length - sizeof(UDPPacket);
    UDPPesudoHeader *ph = malloc(len);
    ph->src_ip = src_ip;
    ph->dest_ip = dest_ip;
    ph->zeros = 0;
    ph->protocol = 17;
    ph->length = udp->length;
    memcpy((void *) &ph->udp, (void *) udp, udp->length);

    uint16_t checksum = ntohs(inet_checksum((void *) ph, len));

    free((void *) ph);
    return checksum;

}

/**
 * Sends a UDP packet with the specified source and destination ports, payload, and destination IP address.
 * The function first builds the UDP packet by allocating memory for it, setting the source and destination ports,
 * copying the payload, and calculating the UDP checksum. Then it sends the packet by calling the send_ip_packet function.
 *
 * @param src_port The source port of the UDP packet.
 * @param dest_port The destination port of the UDP packet.
 * @param payload A pointer to the payload data of the UDP packet.
 * @param payload_len The length of the payload data.
 * @param dest_ip The destination IP address of the UDP packet.
 */
errval_t send_udp_packet(uint16_t src_port, uint16_t dest_port, uint8_t *payload, size_t payload_len, uint32_t dest_ip){
    // Build the UDP packet
    size_t total_len = sizeof(UDPPacket) + payload_len;
    UDPPacket *pck = malloc(total_len);
    pck->src_port = src_port;
    pck->dest_port = dest_port;
    pck->length = total_len;
    memcpy(pck->payload, payload, payload_len);
    pck->checksum = 0;
    pck->checksum = udp_checksum(pck, st->my_ip, dest_ip);

    // Send the packet
    errval_t err = send_ip_packet((uint8_t *)pck, total_len, 17, dest_ip);

    free((void *) pck);
    return err;
}

/**
 * Responds to a received UDP packet by echoing back its payload to the source IP address and port.
 *
 * @param pck A pointer to the received IPv4 packet containing the UDP packet to echo.
 */
static void udp_echo(IPv4Packet *pck){
    UDPPacket *udp = (UDPPacket *) pck->payload;
    send_udp_packet(ECHO_PORT, udp->src_port, udp->payload, udp->length - sizeof(UDPPacket), pck->header.src_ip);
}

static void udp_upload_speedtest(IPv4Packet *pck){
    UDPPacket *udp = (UDPPacket *) pck->payload;
    // payload of udp should contains "ip port" of the speedtest, parse them
    char *ip = (char *) udp->payload;
    char *port = strchr(ip, ' ') + 1;
    ip[port - 1 - ip] = '\0';
    uint8_t port_len = udp->length - sizeof(UDPPacket) - strlen(ip) - 1;
    port[port_len] = '\0';

    uint16_t port_num = atoi(port);
    uint32_t ip_num = str_to_ip(ip);

    // maximum udp payload
    uint8_t *payload = malloc(1472);
    memset(payload, 0, 1472);

    //send the start command
    send_udp_packet(UPLOAD_SPEEDTEST_PORT, port_num, (uint8_t *) "start", 5, ip_num);

    // send the udp payload for 10 seconds
    systime_t start = systime_now();
    while (1) {
        if (systime_to_us(systime_now() - start) / 1000000 >= 10) {
            break;
        }
        send_udp_packet(UPLOAD_SPEEDTEST_PORT, port_num, payload, sizeof(payload), ip_num);
    }

    //send the stop command
    send_udp_packet(UPLOAD_SPEEDTEST_PORT, port_num, (uint8_t *) "stop", 4, ip_num);
    free(payload);
}

static void udp_speedtest(IPv4Packet *pck){
    UDPPacket *udp = (UDPPacket *) pck->payload;

    if(strncmp((char *) udp->payload, "start", 5) == 0){
        //reset the speedtest
        NET_DEBUG("start speedtest\n");
        memset(&current_speedtest, 0, sizeof(struct speedtest));
        current_speedtest.start = systime_now();
    } 
    
    else if(strncmp((char *) udp->payload, "stop", 4) == 0){
        NET_DEBUG("stop speedtest\n");
        current_speedtest.end = systime_now();
        // Calculate the number of bits
        uint64_t bits = current_speedtest.bytes * 8;

        // Calculate the time in seconds
        long time_us = systime_to_us(current_speedtest.end - current_speedtest.start);
        double time = time_us / 1000000.0;

        NET_DEBUG("time %f bits received %llu\n", time, bits);
        
        double speed = bits / (1024.0 * 1024.0 * time);

        NET_DEBUG("Speed: %.02f Mbps\n", speed);
        char buf[32];
        snprintf(buf, 32, "Speed: %.02f Mbps\n", speed);
        send_udp_packet(SPEEDTEST_PORT, udp->src_port, (uint8_t *) buf, strlen(buf), pck->header.src_ip);
    }

    else {
        // packet is part of a speedtest
        current_speedtest.bytes += pck->header.total_length;
    }
}

/**
 * Handles UDP packets that are sent to internal services, such as the echo service.
 *
 * @param pck A pointer to the received IPv4 packet containing the UDP packet to handle.
 */
static void internal_services(IPv4Packet *pck){
    UDPPacket *udp = (UDPPacket *) pck->payload;
    switch(udp->dest_port){
        case ECHO_PORT:
            NET_DEBUG("UDP echo service\n");
            udp_echo(pck);
            break;
        case SPEEDTEST_PORT:
            NET_DEBUG("UDP speedtest service\n");
            udp_speedtest(pck);
            break;
        case UPLOAD_SPEEDTEST_PORT:
            NET_DEBUG("UDP upload speedtest service\n");
            udp_upload_speedtest(pck);
            break;
        default:
            NET_DEBUG("Unknown UDP service\n");
            break;
    }
}

/**
 * Registers a UDP service with the specified port number and process ID.
 *
 * @param port The port number to register the service on.
 * @param pid The process ID of the process that provides the service.
 */
errval_t register_port(uint16_t port, domainid_t pid){

    thread_mutex_lock(&udp_services_mutex);

    // Check if the port is already registered
    void * pid_e = collections_hash_find(udp_services, port);

    if(pid_e != NULL){
        return NET_ERR_PORT_BUSY;
    }

    // Register the port
    void *pid_hash = malloc(sizeof(domainid_t));
    memcpy(pid_hash, &pid, sizeof(domainid_t));
    collections_hash_insert(udp_services, port, (void *) pid_hash);

    thread_mutex_unlock(&udp_services_mutex);

    NET_DEBUG("Registered service on port %d\n", port);

    return SYS_ERR_OK;
}

/**
 * Deregisters a UDP service with the specified port number.
 *
 * @param port The port number to deregister the service from.
*/
void deregister_port(uint16_t port){
    thread_mutex_lock(&udp_services_mutex);

    void * pid = collections_hash_find(udp_services, port);
    if(pid == NULL){
        return;
    }

    collections_hash_delete(udp_services, port);
    thread_mutex_unlock(&udp_services_mutex);
}

/**
 * Handles a received UDP packet by checking if the checksum is correct, and if so, checking if there is a service
 * listening on the destination port. If there is, the packet is forwarded to the service. If not, the packet is
 * dropped.
 *
 * @param pck A pointer to the received IPv4 packet containing the UDP packet to handle.
 */
void net_handle_udp(IPv4Packet *pck){
    UDPPacket *udp = (UDPPacket *) pck->payload;
    
    //check if checksum is correct
    uint16_t checksum = udp->checksum;
    udp->checksum = 0;

    if(checksum != 0 && checksum != udp_checksum(udp, pck->header.src_ip, pck->header.dest_ip)){
        NET_DEBUG("UDP Checksum is incorrect, dropping packet\n");
        return;
    }

    uint16_t dest_port = udp->dest_port;
    
    thread_mutex_lock(&udp_services_mutex);
    void * pid_p = collections_hash_find(udp_services, dest_port);
    thread_mutex_unlock(&udp_services_mutex);


    if(pid_p == NULL){
        NET_DEBUG("No service listening on port %d\n", dest_port);
        return;
    }

    domainid_t pid;
    memcpy(&pid, pid_p, sizeof(domainid_t));

    if(pid == disp_get_domain_id()){
        internal_services(pck);
    } else {
        // Forward the packet to the service
        NET_DEBUG("Forwarding UDP packet to service on port %d\n", dest_port);
        
        //Add it to the handler write queue - This is for polling
        // net_add_lmp_req((void *) pck, pck->header.total_length, pid);

        // No polling
        errval_t *ret;
        errval_t err = aos_rpc_net_answer((void *) pck, pck->header.total_length, &ret, pid, NET_PACKET);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "Failed to send message to process from network");
        } else {
            if(*ret == PROC_MGMT_ERR_DOMAIN_NOT_RUNNING){
                NET_DEBUG("Process not running, deleting its services\n");
                deregister_port(dest_port);
            }
            free(ret);
        }

    }

}

/**
 * Initializes the UDP layer by registering the internal services.
 */
void udp_init(void){
    thread_mutex_init(&udp_services_mutex);
    collections_hash_create(&udp_services, arp_clean);
    // Register the UDP internal services
    for(int i = 0; i < N_SERVICES; i++){
        register_port(services[i], disp_get_domain_id());
    }

}