#include <aos/aos.h>
#include <aos/deferred.h>
#include <aos/threads.h>
#include <aos/aos_rpc.h>
#include "network.h"

struct enet_driver_state * st = NULL;
#define MY_IP "192.168.0.69"

/**
 * Sends a packet over the network.
 *
 * @param packet A pointer to the packet data.
 * @param type The Ethernet type of the packet.
 * @param len The length of the packet data.
 * @param mac_dest The MAC address of the destination.
 * @param ip The IP address of the destination.
 */
errval_t net_send_packet(void *packet, uint16_t type, size_t len, mac_addr mac_dest, uint32_t ip){

    // If no MAC address is given, try to resolve it using ARP
    if(mac_dest == NULL){
        uint8_t try = 0;
        mac_dest = malloc(6);
        memset(mac_dest, 0, 6);

        arp_query(ip, mac_dest);

        while(is_mac_null(mac_dest) && try < 3){
            NET_DEBUG("Failed to resolve mac address, trying again\n");
            barrelfish_usleep(500000); //TODO: check if this delay can be lowered
            arp_query(ip, mac_dest);
            thread_yield();
            try++;
        }

        if(is_mac_null(mac_dest)){
            NET_DEBUG("Failed to resolve mac address, dropping packet\n");
            return NET_ERR_MAC_NOT_FOUND;
        }
    }

    // If the packet is too big, drop it
    if(len > 1500){
        NET_DEBUG("Packet is too big, dropping it\n");
        return NET_ERR_PACKET_TOO_BIG;
    }

    //Build the ethernet frame
    size_t total_len = len + sizeof(EthernetFrame);
    EthernetFrame *frame = malloc(total_len);
    memcpy(frame->dest, mac_dest, 6);
    memcpy(frame->src, st->mac_addr, 6);
    frame->type = type;
    memcpy(frame->payload, packet, len);

    // Copy the Ethernet frame to the transmit buffer
    //will use only one buffer for now
    memcpy((void*)st->tx_vaddr, (void *)frame, total_len);
    free((void *) frame);

    //Debug
    // EthernetPacket* epack = malloc(total_len+4);
    // epack->frame_size = total_len;
    // memcpy((void *) &epack->frame, (void *)st->tx_vaddr, total_len);
    // print_eth_packet(epack);

    // Enqueue the transmit buffer to the device queue
    thread_mutex_lock(&st->tx_mutex);
    errval_t err = devq_enqueue((struct devq*) st->txq, st->tx_rid, 0,
                               2048, 0, total_len,
                               0);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to send packet");
        thread_mutex_unlock(&st->tx_mutex);
        return NET_ERR_FAILED_TO_SEND;
    }

    // Wait for the packet to be sent
    struct devq_buf buf;
    while(true){
        err = devq_dequeue((struct devq*) st->txq, &buf.rid, &buf.offset,
                           &buf.length, &buf.valid_data, &buf.valid_length,
                           &buf.flags);
        if(err_is_ok(err)){
            NET_DEBUG("Packet sent\n");
            break;
        }
        thread_yield_dispatcher(NULL_CAP);
    }
    thread_mutex_unlock(&st->tx_mutex);
    return SYS_ERR_OK;
}


/**
 * Handle incoming packets.
 *
 * This function is called in an infinite loop and handles incoming packets.
 * It will call the appropriate handler function for each packet type.
 */
static void net_handle_packets(void){

    struct devq_buf buf;
    errval_t err;

    while(true) {
        err = devq_dequeue((struct devq*) st->rxq, &buf.rid, &buf.offset,
                           &buf.length, &buf.valid_data, &buf.valid_length,
                           &buf.flags);
        if (err_is_ok(err)) {
            NET_DEBUG("Received Packet of size %lu \n", buf.valid_length);

            lvaddr_t packet_addr = (lvaddr_t) buf.valid_data + st->rx_vaddr + buf.offset;
            EthernetPacket *pck;
            generate_eth_packet(packet_addr, buf.valid_length, &pck);
            // print_eth_packet(pck);

            switch((*pck).frame.type){
                case ETH_TYPE_IP:
                    net_handle_ip((IPv4Packet*) (*pck).frame.payload);
                    break;
                case ETH_TYPE_ARP:
                    net_handle_arp((ARPPacket*) (*pck).frame.payload);
                    break;
                default:
                    NET_DEBUG("Unknown packet type: 0x%x\n", (*pck).frame.type);
                    break;
            }

            err = devq_enqueue((struct devq*) st->rxq, buf.rid, buf.offset,
                               buf.length, buf.valid_data, buf.valid_length,
                               buf.flags);            
            
            free(pck);
            assert(err_is_ok(err));
        }
        thread_yield_dispatcher(NULL_CAP);
    }

}

int main(int argc, char **argv){
    (void)argc;
    (void)argv;

    NET_DEBUG("Network is starting\n");
    DEBUG_PRINTF("Remember to connect your ethernet cable otherwise this will remain stuck\n");

    // Allocate memory for the enet_driver_state struct
    st = (struct enet_driver_state*) calloc(1, sizeof(struct enet_driver_state));
    assert(st != NULL);

    //Start the driver
    errval_t err = enet_start(st);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "enet_start failed");
        return err;
    }

    // Print mac and current ip
    print_mac(st->mac_addr);
    st->my_ip = str_to_ip(MY_IP);
    char ip_str[16];
    ip_to_str(ip_str, st->my_ip);
    NET_DEBUG("My IP: %s\n", ip_str);

    // Initialize the transmit mutex - receive only happens in the main thread so it's not needed
    thread_mutex_init(&st->tx_mutex);
    thread_mutex_init(&st->icmp_mutex);

    //Initialize the ARP table
    arp_init();

    // Initialize the UDP interal services
    udp_init();

    struct aos_rpc *main_rpc = malloc(sizeof(struct aos_rpc));
    aos_rpc_create_lmp_chan(main_rpc);
    thread_set_preferred_rpc((void *) main_rpc);

    // Handler thread (listens for incoming requests from other processes)
    struct thread *t = thread_create(net_handle_req_init, NULL);
    thread_detach(t);
    NET_DEBUG("Starting handling packets\n");

    aos_rpc_server_ready();
    net_handle_packets();

}