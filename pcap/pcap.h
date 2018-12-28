
#ifndef _PCAP_H_
#define _PCAP_H_
#include <stdio.h>
#include <net/ethernet.h> // struct ether_header
#include <netinet/ip.h> // struct iphdr

/* analyze.c */
int analyze_packet(uint8_t* data, int size);


/* print.c */
int print_ether_header(struct ether_header *eh, FILE *fp);
int print_arp(struct ether_arp* eth_arp, FILE *fp);
int print_ip_header(struct iphdr *ip_hdr, uint8_t* option, int option_len, FILE* fp);
int print_icmp(struct icmp* icmp, FILE *fp);

/* checksum.c */
uint16_t checksum(uint16_t* buf, int size);
#endif
