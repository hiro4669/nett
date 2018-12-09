#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // struct ether_header

#include "pcap.h"

int analyze_packet(uint8_t* data, int size) {

    uint8_t* ptr;
    int lest;
    struct ether_header* e_head;

    ptr = data;
    lest = size;
    e_head = (struct ether_header*)ptr;

//    printf("%04x\n", ntohs(e_head->ether_type));

    switch(ntohs(e_head->ether_type)) {
        case ETHERTYPE_ARP: {
            print_ether_header(e_head, stdout);
            break;
        }
        case ETHERTYPE_IP: {
            print_ether_header(e_head, stdout);
            break;
        }
        default: {
            break;
        }
    }




    return 0;
}
