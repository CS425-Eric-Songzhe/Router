#ifndef MY_ETHHDR_H 
#define MY_ETHHDR_H  
#include "sr_protocol.h"  

void make_ethhdr(struct sr_ethernet_hdr* ethhdr, uint16_t type, uint8_t* src, uint8_t* dst); 
void print_ethhdr(struct sr_ethernet_hdr* ethhdr);  

#endif
