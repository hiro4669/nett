#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // struct ether_header


#include "pcap.h"

int analyze_arp(struct ether_arp *eth_arp, int size) {

    if (size < sizeof(struct ether_arp)) {
        fprintf(stderr, "size(%d) is less than arp header(%d)\n", size, (int)sizeof(struct ether_arp));
        return -1;
    }
    print_arp(eth_arp, stdout);

    return 0;
}


int analyze_packet(uint8_t* data, int size) {

    uint8_t* ptr;
    int lest;
    struct ether_header* e_head;

    ptr = data;
    lest = size;
    e_head = (struct ether_header*)ptr;

    ptr += sizeof(struct ether_header);
    lest -= sizeof(struct ether_header);

    fprintf(stderr, "\nPacket[%dbytes]\n", size);
    switch(ntohs(e_head->ether_type)) {
        case ETHERTYPE_ARP: {
            print_ether_header(e_head, stdout);
            analyze_arp((struct ether_arp*)ptr, lest);
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
