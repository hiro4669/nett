#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pcap.h"

static char* ether_ntoa_r(uint8_t* hwaddr, char* buf, socklen_t size) {
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
        hwaddr[0],
        hwaddr[1],
        hwaddr[2],
        hwaddr[3],
        hwaddr[4],
        hwaddr[5]
    );
    return buf;
}

int print_ether_header(struct ether_header *eh, FILE *fp) {
    char buf[80];

    fprintf(fp, "ether_header-----------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%04x", ntohs(eh->ether_type));
    switch(ntohs(eh->ether_type)) {
        case ETHERTYPE_IP: {
            fprintf(fp, "(IP)\n");
            break;
        }
        case ETHERTYPE_IPV6: {
            fprintf(fp, "(IPV6)\n");
            break;
        }
         case ETHERTYPE_ARP: {
            fprintf(fp, "(ARP)\n");
            break;
        }
        default: {
            fprintf(fp, "(unknown)\n");
            break;
        }
    }


    return 0;
}
