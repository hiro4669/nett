#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>


static int init_row_socket(char *device, int promMode, int ipOnly) {
    struct ifreq       ifreq;
    struct sockaddr_ll sa;
    int soc;

    if (ipOnly) {
        /* PF_PACKET for Ethernet */
        /* ETH_P_IP is defined in /usr/include/linux/if_ether.h */
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
            perror("socket");
            return -1;
        }
    } else {
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            perror("socket");
            return -1;
        }
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl");
        close(soc);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    if (ipOnly) {
        sa.sll_protocol = htons(ETH_P_IP);
    } else {
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    sa.sll_ifindex = ifreq.ifr_ifindex;
//    printf("index = %d\n", ifreq.ifr_ifindex);
//    printf("index = %d\n", sa.sll_ifindex);


    if (bind(soc, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(soc);
        return -1;
    }

    if (promMode) {
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
            perror("ioctl");
            close(soc);
            return -1;
        }
        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
            perror("ioctl");
            close(soc);
            return -1;
        }
    }
    return soc;
}


char* my_ether_ntoa_r(uint8_t *hwaddr, char* buf, socklen_t size) {
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

/*
/usr/include/linux/if_ether.h

#define ETH_P_LOOP      0x0060          // Ethernet Loopback packet
#define ETH_P_PUP       0x0200          // Xerox PUP packet
#define ETH_P_PUPAT     0x0201          // Xerox PUP Addr Trans packet
#define ETH_P_IP        0x0800          // Internet Protocol packet
#define ETH_P_X25       0x0805          // CCITT X.25
#define ETH_P_ARP       0x0806
....

/usr/include/net/ethernet.h

#define ETHERTYPE_PUP           0x0200          // Xerox PUP
#define ETHERTYPE_SPRITE        0x0500          // Sprite
#define ETHERTYPE_IP            0x0800          // IP
#define ETHERTYPE_ARP           0x0806          // Address resolution
#define ETHERTYPE_REVARP        0x8035          // Reverse ARP
#define ETHERTYPE_AT            0x809B          // AppleTalk protocol
#define ETHERTYPE_AARP          0x80F3          // AppleTalk ARP
#define ETHERTYPE_VLAN          0x8100          // IEEE 802.1Q VLAN tagging
#define ETHERTYPE_IPX           0x8137          // IPX
#define ETHERTYPE_IPV6          0x86dd          // IP protocol version 6
#define ETHERTYPE_LOOPBACK      0x9000          //




struct ether_neader {

}
*/
int print_ether_header(struct ether_header *eh, FILE *fp) {
    char buf[80];

    fprintf(fp, "ether_header-----------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type =%04x", ntohs(eh->ether_type));
    switch(ntohs(eh->ether_type)) {
        case ETH_P_IP: {
            fprintf(fp, "(IP)\n");
            break;
        }
        case ETH_P_IPV6: {
            fprintf(fp, "(IPV6)\n");
            break;
        }
        case ETH_P_ARP: {
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



int main(int argc, char *argv[]) {
    int soc;
    int size;
    uint8_t buf[2048];

    if (argc <= 1) {
        fprintf(stderr, "l2capt device-name\n");
        return -1;
    }
    if ((soc = init_row_socket(argv[1], 0, 0)) == -1) {
        fprintf(stderr, "init_row_socket error %s\n", argv[1]);
        return -1;
    }

    printf("soc = %d\n", soc);


    while (1) {
        if ((size = read(soc, buf, sizeof(buf))) <= 0) {
            perror("read");
        } else {
            if (size >= sizeof(struct ether_header)) {
                printf("size = %d\n", (int)size);
                print_ether_header((struct ether_header*)buf, stdout);
            } else {
                fprintf(stderr, "read size(%d) < %d", size, (int)sizeof(struct ether_header));
            }
        }
    }


    return 0;
}
