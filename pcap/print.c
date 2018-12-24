#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pcap.h"

/* hardware type from /usr/include/net/if_arp.h */
static char *hrd[] = {
    "From KA9Q: NET/ROM pseudo",
    "Ethernet 10/100Mbps.",
    "Experimental Ethernet",
    "AX.25 Level 2",
    "PROnet token ring",
    "Chaosnet.",
    "IEEE 802.2 Ethernet/TR/TB."
    "ARCnet",
    "APPLEtalk"
    "undefined",
    "undefined",
    "undefined",
    "undefined",
    "undefined",
    "undefined"
    "Frame Relay DLCI"
    "undefined",
    "undefined",
    "undefined",
    "ATM",
    "undefined",
    "undefined",
    "undefined",
    "Metricom STRIP (new IANA id)"
    "IEEE 1394 IPv4 - RFC 2734"
    "undefined",
    "undefined",
    "EUI-64",
    "undefined",
    "undefined",
    "undefined",
    "undefined",
    "InfiniBand"
};

static char *opcode[] = {
    "undefined",
    "ARP Request",
    "ARP Reply",
    "RARP Request",
    "RARP Reply",
    "undefined",
    "undefined",
    "undefined",
    "InARP Request",
    "InARP Reply",
    "(ATM)ARP NAK"
};

/* show mac address */
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

/* show ip address */
static char* arp_ip2str(uint8_t* ip, char *buf, socklen_t size) {
    snprintf(buf,size,"%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);
    return(buf);
}

int print_arp(struct ether_arp* eth_arp, FILE *fp) {
    char buf[80];

    fprintf(fp, "arp-----------------------------------\n");
    fprintf(fp, "arp_hrd=%u", ntohs(eth_arp->arp_hrd));
    if (ntohs(eth_arp->arp_hrd) <= 32) {
        fprintf(fp, "(%s),", hrd[ntohs(eth_arp->arp_hrd)]);
    } else {
        fprintf(fp, "(unknown/undefined),");
    }
    fprintf(fp, "ar_pro = %u", ntohs(eth_arp->arp_pro));
    switch(ntohs(eth_arp->arp_pro)) {
        case ETHERTYPE_IP: {
            fprintf(fp, "(IP)\n");
            break;
        }
        case ETHERTYPE_ARP: {
            fprintf(fp, "(ARP)\n");
            break;
        }
        case ETHERTYPE_REVARP: {
            fprintf(fp, "(Reverse ARP)\n");
            break;
        }
        case ETHERTYPE_IPV6: {
            fprintf(fp, "(IPV6)\n");
            break;
        }
        default: {
            fprintf(fp, "(unknown)\n");
            break;
        }
    }
    fprintf(fp, "arp_hwd_len = %u,", eth_arp->arp_hln);
    fprintf(fp, "arp_pro_len = %u\n", eth_arp->arp_pln);
    fprintf(fp, "arp_op      = %u,", ntohs(eth_arp->arp_op));
    if (ntohs(eth_arp->arp_op) <= 10) {
        fprintf(fp, "(%s)\n", opcode[ntohs(eth_arp->arp_op)]);
    } else {
        fprintf(fp, "(undefined)\n");
    }

    fprintf(fp, "arp_sha = %s\n", ether_ntoa_r(eth_arp->arp_sha, buf, sizeof(buf)));
    fprintf(fp, "arp_spa = %s\n", arp_ip2str(eth_arp->arp_spa, buf, sizeof(buf)));
    fprintf(fp, "arp_tha = %s\n", ether_ntoa_r(eth_arp->arp_tha, buf, sizeof(buf)));
    fprintf(fp, "arp_tpa = %s\n", arp_ip2str(eth_arp->arp_tpa, buf, sizeof(buf)));

    return 0;
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
