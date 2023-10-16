#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/lmp_chan.h>
#include <aos/deferred.h>
#include <include/client/network_client.h>

errval_t client_icmp_ping(uint32_t dest_ip, char **ping_rest){
    size_t len;
    errval_t err = aos_rpc_net_request(&dest_ip, sizeof(uint32_t), ICMP_PING, (void **) ping_rest, &len);

    return err;
}

errval_t client_udp_service(uint16_t port){
    void *buff;
    size_t len;

    errval_t err = aos_rpc_net_request(&port, sizeof(uint16_t), UDP_REGISTER, &buff, &len);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to register UDP service");
        return err;
    }

    memcpy(&err, buff, sizeof(errval_t));
    free(buff);
    
    return err;
}

errval_t client_udp_listener(IPv4Packet **pck){


    void *buff;
    size_t len = 0;
    enum net_type type;

    // OLD VERSION WITHOUT POLLING PRONE TO RACE CONDITIONS
    errval_t err = aos_rpc_net_get_request((void **) &buff, &len, &type);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to get request from network process");
        return err;
    }

    //the packet is after the pid
    *pck = malloc(len - sizeof(domainid_t));
    memcpy((void *) *pck, buff + sizeof(domainid_t), len - sizeof(domainid_t));
    free(buff);

    // while(len == 0){
    //     errval_t err = aos_rpc_net_request(NULL, 0, POLL_REQ, &buff, &len);
    //     if(err_is_fail(err)){
    //         DEBUG_ERR(err, "Failed to poll network process");
    //         return err;
    //     }
    //     barrelfish_usleep(1000);
    //     thread_yield();
    // }

    // *pck = malloc(len);
    // memcpy((void *) *pck, buff, len);
    // free(buff);


    return SYS_ERR_OK;
}

errval_t client_send_udp_packet(uint16_t src_port, uint16_t dest_port, uint8_t *payload, size_t payload_len, uint32_t dest_ip){
    // Serialize the data
    size_t len = sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + payload_len;
    void *buff = malloc(len);
    
    // First dest_ip, then dest_port, then src_port, then payload
    memcpy(buff, &dest_ip, sizeof(uint32_t));
    memcpy(buff + sizeof(uint32_t), &dest_port, sizeof(uint16_t));
    memcpy(buff + sizeof(uint32_t) + sizeof(uint16_t), &src_port, sizeof(uint16_t));
    memcpy(buff + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t), payload, payload_len);

    void *ret;
    size_t ret_len;

    errval_t err = aos_rpc_net_request(buff, len, UDP_SEND, &ret, &ret_len);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to send UDP packet");
        free(buff);
        return err;
    }

    memcpy(&err, ret, sizeof(errval_t));
    free(ret);
    free(buff);
    return err;
}

errval_t client_echo_udp(IPv4Packet *pck){
    // Get the payload
    UDPPacket *udp = (UDPPacket *) pck->payload;
    uint8_t *payload = udp->payload;
    size_t payload_len = udp->length - sizeof(UDPPacket);

    // Send the payload back
    errval_t err = client_send_udp_packet(udp->dest_port, udp->src_port, payload, payload_len, pck->header.src_ip);
    return err;
}