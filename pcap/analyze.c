#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // struct ether_header
#include <netinet/if_ether.h> // ether_arp
#include <netinet/ip.h> // struct iphdr

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pcap.h"

int analyze_arp(struct ether_arp *eth_arp, int size) {

    if (size < sizeof(struct ether_arp)) {
        fprintf(stderr, "size(%d) is less than arp header(%d)\n", size, (int)sizeof(struct ether_arp));
        return -1;
    }
    print_arp(eth_arp, stdout);

    return 0;
}

int analyze_ip(struct iphdr* ip_hdr, int size) {

    uint8_t* ptr;
    int lest = size;
    int option_len;
    uint8_t* option;

    if (lest < sizeof(struct iphdr)) {
        fprintf(stderr, "lest(%d) < sizeof(struct ipadr)\n", lest);
    }


    printf("heder len = %d\n", ip_hdr->ihl * 4);
    ptr = (uint8_t*)ip_hdr;
    for (int i = 0; i < 20; ++i) {
        if (i % 10 == 0) printf("\n");
        printf("%02x ", ptr[i]);
    }
    printf("\n");


//    printf("lest        = %d\n", lest);
    lest -= sizeof(struct iphdr);
    option = ptr = (uint8_t*)&ip_hdr[1];

    /*
    printf("ip_hdr addr = %p\n", ip_hdr);
    printf("pay    addr = %p\n", ptr);
    printf("lest        = %d\n", lest);
    */
    option_len = ip_hdr->ihl * 4 - sizeof(struct iphdr);
//    printf("option len = %d\n", option_len);
    if (option_len > 0) {
        if (option_len >= 1500) {
            fprintf(stderr, "IP optionlen(%d): too big\n", option_len);
            return -1;
        }
        ptr += option_len;
        lest -= option_len;
    }

//    int r = checksum((uint16_t*)ip_hdr, ip_hdr->ihl * 4);
//    printf("r = %d\n", r);

    if(checksum((uint16_t*)ip_hdr, ip_hdr->ihl * 4)) {
        fprintf(stderr, "bad ip checksum\n");
        return -1;
    }

    print_ip_header(ip_hdr, option, option_len, stdout);



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
            analyze_ip((struct iphdr*)ptr, lest);
            break;
        }
        default: {
            break;
        }
    }




    return 0;
}
