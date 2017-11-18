#ifndef MY_ARP_H
#define MY_ARP_H

#include <time.h>
#include <stdbool.h>
#include <stdio.h> 
#include <stdint.h> 
#include <stdlib.h> 
#include <string.h>
#include "sr_protocol.h"

#define CACHE_SIZE 100
#define CACHE_EXPTIME 15

struct arp_cache_entry {
  uint32_t            ar_sip;                     // sender ip addr
  uint8_t             ar_sha[ETHER_ADDR_LEN];     // sender hardware addr
  time_t              timeCached;                 // timestamp
  int                 valid;                      // timeout
};

void make_ARP_hdr(struct sr_arphdr* arp_hdr,         
	     uint16_t    hrd_type,
             uint16_t    pro_type,
             uint8_t     h_len,
             uint8_t     p_ln,
             uint16_t    op,
             uint8_t*    sh_addr,
             uint32_t    sp_addr,
             uint8_t*    th_addr,
             uint32_t    tp_addr);
void handle_ARP(struct sr_instance* sr, uint8_t* pkt, unsigned int len, char* interface);
void send_ARP_reply(struct sr_instance* sr, uint8_t* pkt, unsigned int len, char* interface, struct sr_if* ifnode);
void send_ARP_request(struct sr_instance* sr, struct sr_if* ifnode, uint32_t tp_addr);
int is_ARP_request(struct sr_arphdr* arp_hdr);
int is_ARP_reply(struct sr_arphdr* arp_hdr);
//milestone 2
void arpInitCache();
void arpCacheEntry(struct sr_arphdr* arp_hdr); 
void arpUpdateCache(); 
uint8_t* arpReturnEntryMac(int adr); 
void arpDumpCache(); 
void arpDumpHeader(struct sr_arphdr* arp_hdr);




#endif
