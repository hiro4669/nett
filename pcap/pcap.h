
#ifndef _PCAP_H_
#define _PCAP_H_
#include <stdio.h>
#include <net/ethernet.h> // struct ether_header

/* analyze.c */
int analyze_packet(uint8_t* data, int size);


/* print.c */
int print_ether_header(struct ether_header *eh, FILE *fp);

#endif
