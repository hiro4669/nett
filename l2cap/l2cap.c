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


static init_row_socket(char *device, int promMode, int ipOnly) {
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

    return soc;
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

    while (1) {
        if ((size = read(soc, buf, sizeof(buf))) <= 0) {
            perror("read");
        } else {
            if (size >= sizeof(struct ether_header)) {
                printf("size = %d\n", size);
            } else {
                fprintf(stderr, "read size(%d) < %d", size, sizeof(struct ether_header));
            }
        }
    }

    return 0;
}
