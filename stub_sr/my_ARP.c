/*
 * Authors: Eric Evans, Songzhe Zhu
 * Date: 11/10/17
 *
 * Description: 
 * Handles ARP packet making/sending/parsing 
 */


#include <time.h>
#include <stdbool.h>
#include <stdio.h> 
#include <stdint.h> 
#include <stdlib.h> 
#include <string.h>
#include "sr_if.h"
#include "sr_protocol.h"
#include "my_ethhdr.h"
#include "my_ARP.h"
#include "sr_router.h"

/*----------------------------------------------------------------------
 * ARP Cache data structure
 *
 * stores <protocol type, sender protocol address, sender hardware address>
 * triplet's along with valid/invalid flag based on timeout
 *---------------------------------------------------------------------*/
struct arp_cache_entry arpCache[CACHE_SIZE];


// make ARP header with fields
void make_ARP_hdr(struct sr_arphdr* arp_hdr,         
	     uint16_t    hrd_type,
             uint16_t    pro_type,
             uint8_t     h_len,
             uint8_t     p_ln,
             uint16_t    op,
             uint8_t*    sh_addr,
             uint32_t    sp_addr,
             uint8_t*    th_addr,
             uint32_t    tp_addr){   

	     uint32_t sp_buf, tp_buf;
             uint8_t sh_buff[ETHER_ADDR_LEN], th_buf[ETHER_ADDR_LEN];
             int i;
             arp_hdr->ar_hrd = hrd_type;
             arp_hdr->ar_pro = pro_type;
             arp_hdr->ar_hln = h_len;
             arp_hdr->ar_pln = p_ln;
             arp_hdr->ar_op = op;

             sp_buf = sp_addr;
             tp_buf = tp_addr;
             arp_hdr->ar_sip = sp_buf;
             arp_hdr->ar_tip = tp_buf;

             for (i = 0; i < ETHER_ADDR_LEN; i++) {
                sh_buff[i] = sh_addr[i];
                th_buf[i] = th_addr[i];
             }
             for (i = 0; i < ETHER_ADDR_LEN; i++) {
                arp_hdr->ar_sha[i] = sh_buff[i];
                arp_hdr->ar_tha[i] = th_buf[i];
             }
}


// switch over types and send/cache
void handle_ARP(struct sr_instance* sr, uint8_t* pkt, unsigned int len, char* interface){   
  
  struct sr_arphdr * arp_hdr = (struct sr_arphdr*)(pkt + 14);
  struct sr_if * ifnode = sr->if_list; 
  struct in_addr req, rep;     
  int i;

  if(is_ARP_request(arp_hdr)){
         req.s_addr = arp_hdr->ar_tip;
         printf("ARP Req: Broadcasting %s?\n", inet_ntoa(req));         
         while (ifnode) {
             if (ifnode->ip == arp_hdr->ar_tip) {
                 send_ARP_reply(sr, pkt, len, interface, ifnode);
                 return;
             } else {
                 ifnode = ifnode->next;
             }
         }
          if (!ifnode) {
             printf("!! ARP Req: Failed to Find %s\n", inet_ntoa(req));         }
  }
  if(is_ARP_reply(arp_hdr)){
          rep.s_addr = arp_hdr->ar_sip;
          // log
          printf("ARP Reply: %s @ ", inet_ntoa(rep));

          for (i = 0; i < ETHER_ADDR_LEN; i++)
             printf("%2.2x", arp_hdr->ar_sha[i]);
         
	  printf("\n");
  }  
}


// send ARP reply packet
void send_ARP_reply(struct sr_instance* sr, uint8_t* pkt, unsigned int len, char* interface, struct sr_if* ifnode){   

     struct sr_ethernet_hdr * ethernetHdr = (struct sr_ethernet_hdr*)pkt;
     struct sr_arphdr * arp_hdr = (struct sr_arphdr*)(pkt+14);
     struct in_addr rep;
     int i;
     make_ARP_hdr(arp_hdr, arp_hdr->ar_hrd, arp_hdr->ar_pro, arp_hdr->ar_hln, arp_hdr->ar_pln, htons(ARP_REPLY), sr_get_interface(sr, interface)->addr, sr_get_interface(sr, interface)->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
     make_ethhdr(ethernetHdr, ETHERTYPE_ARP, ifnode->addr, ethernetHdr->ether_shost);

     // send our newly generated arp reply away!
     sr_send_packet(sr, pkt, len, interface);

     // log on send
     rep.s_addr = arp_hdr->ar_sip;
     printf("ARP Reply: %s @ ", inet_ntoa(rep));
     for (i = 0; i < ETHER_ADDR_LEN; i++) {
         printf("%2.2x", arp_hdr->ar_sha[i]);
     } 
     printf ("\n");

}


// Send sr_instance packet with ARP info
void send_ARP_request(struct sr_instance* sr, struct sr_if* ifnode, uint32_t tp_addr){   

     struct in_addr req;               
     uint8_t broadcast[ETHER_ADDR_LEN];
     int i;      
     uint8_t* requestPkt = malloc(42 * sizeof(uint8_t));

     if (requestPkt == NULL) {
         fprintf(stderr, "ERROR\n");         
         return;
     }
     memset(requestPkt, 0, 42 * sizeof(uint8_t));      

     // new headers 
     struct sr_ethernet_hdr* ethernetHdr = (struct sr_ethernet_hdr*)requestPkt;     
     struct sr_arphdr* arp_hdr = (struct sr_arphdr*)(requestPkt+14);
     
     // make broadcast
     for (i = 0; i < ETHER_ADDR_LEN; i++)
         broadcast[i] = 0xff;

     // make headers
     make_ARP_hdr(arp_hdr, htons(ARPHDR_ETHER), htons(ETHERTYPE_IP), 6, 4, htons(ARP_REQUEST), ifnode->addr, ifnode->ip, broadcast, tp_addr);
     make_ethhdr(ethernetHdr, ETHERTYPE_ARP, ifnode->addr, broadcast);
     
     // SEND!
     sr_send_packet(sr, requestPkt, 42, ifnode->name);
      
     // log
     req.s_addr = tp_addr;
     printf("ARP Req: Broadcasting %s?\n", inet_ntoa(req));

     free(requestPkt);
}


// True if ARP header says it's a request
int is_ARP_request(struct sr_arphdr* arp_hdr){   

  int ret = ntohs(arp_hdr->ar_op) == ARP_REQUEST;

  if(ret)
    printf("IS an ARP request\n");
  else
    printf("NOT an ARP request\n");

  return ret;
}


// True if ARP header says it's a reply
int is_ARP_reply(struct sr_arphdr* arp_hdr){   

  int ret = ntohs(arp_hdr->ar_op) == ARP_REPLY;    

  if(ret) 
    printf("IS an ARP reply\n"); 
  else  
    printf("NOT an ARP reply\n");

  return ret;
}

//Milestone 2:

//Set up the arp cache
void arpInitCache() {
	int i;
	for (i = 0; i < CACHE_SIZE; i++) {
		arpCache[i].valid = 0;     
	} 
}

/*-----------------------------------------------------------------------------
 * Method: void arpCacheEntry(struct sr_arphdr* arpHdr)
 *
 * stores new ARP info in network byte order in our cache
 *---------------------------------------------------------------------------*/
void arpCacheEntry(struct sr_arphdr* arpHdr)
{
  int i,j;

  /* find first empty slot in our cache */
  for (i = 0; i < CACHE_SIZE; i++) {
	if (arpCache[i].valid == 0)
	  break;
  }

  /* extract ARP info from arpHdr and cache it */
  arpCache[i].ar_sip = arpHdr->ar_sip;
  for (j = 0; j < ETHER_ADDR_LEN; j++)
	arpCache[i].ar_sha[j] = arpHdr->ar_sha[j];

  // timestamp and make valid
  arpCache[i].timeCached = time(NULL);
  arpCache[i].valid = 1;

  /* TODO
   *
   * LOOK THROUGH PACKET CACHE TO SEE IF WE CAN SEND SOMETHING WITH THE NEWLY
   * ADDED ARP ENTRY
   */
}

/*-----------------------------------------------------------------------------
 * Method: int arpSearchCache(struct ip* ipHdr)
 *
 * searches our arp cache to see if we have a valid hwaddr
 * that matches the target ipaddr we need to send to
 *---------------------------------------------------------------------------*/
int arpSearchCache(uint32_t ipaddr)
{
  /* look through cache for matching proto and sip with valid flag = 0 */
  /* returns index of that entry if found, otherwise returns -1 */
  int i;

  for (i = 0; i < CACHE_SIZE; i++) {
	if (arpCache[i].valid == 1) {
	  if (arpCache[i].ar_sip == ipaddr) {
		return i;
	  }
	}
  }

  return -1;
}

/*-----------------------------------------------------------------------------
 * Method: void arpUpdateCache()
 *
 * finds stale arp entries in our cache and invalidates them
 *---------------------------------------------------------------------------*/
void arpUpdateCache()
{
  /* find entries older than STALE_TIME seconds and set valid bit to 0 */
  int i;

  for (i = 0; i < CACHE_SIZE; i++) {
	/* if valid and timestamp is older than 15 seconds, mark invalid */
	if (arpCache[i].valid == 1) {
	  if (difftime(time(NULL), arpCache[i].timeCached) > CACHE_EXPTIME) {
		printf("-- ARP: Marking ARP cache entry %d invalid\n", i);
		arpCache[i].valid = 0;
	  }
	}
  }
}

/*-----------------------------------------------------------------------------
 * Method: uint8_t* arpReturnEntryMac(int entry)
 *
 * returns a pointer to the arpCache[entry] source hardware address
 *---------------------------------------------------------------------------*/
uint8_t* arpReturnEntryMac(int entry)
{
  return (uint8_t*)&arpCache[entry].ar_sha;
}

/*-----------------------------------------------------------------------------
 * Method: void armDumpCache()
 *
 * prints all of the cache entries to stdout
 *---------------------------------------------------------------------------*/
void arpDumpCache()
{
  int i,j;

  for (i = 0; i < CACHE_SIZE; i++) {
	if (arpCache[i].valid == 1) {
	  printf("CACHE ENTRY: %d\n", i);
	  printf("ar_sip: %8.8x\n", arpCache[i].ar_sip);
	  printf("ar_sha: ");
	  for (j = 0; j < ETHER_ADDR_LEN; j++)
		printf("%2.2x", arpCache[i].ar_sha[j]);
	  printf("\n");
	  printf("valid: %d\n", arpCache[i].valid);
	  //printf("seconds: %S\n", arpCache[i].timeCached);
	}
  }
}

/*-----------------------------------------------------------------------------
 * Method: void arpDumpHeader(struct sr_arphdr* )
 *
 * Prints fields in the ARP header to stdout
 *---------------------------------------------------------------------------*/
void arpDumpHeader(struct sr_arphdr* arpHdr)
{
  struct in_addr ar_ip;
  int i;

  printf("==== ARP HEADER ====\n");
  fprintf(stdout, "Hardware Type: %4.4x\n", ntohs(arpHdr->ar_hrd));
  fprintf(stdout, "Protocol Type: %4.4x\n", ntohs(arpHdr->ar_pro));
  fprintf(stdout, "Hardware Address Length: %2.2x\n", arpHdr->ar_hln);
  fprintf(stdout, "Protocol Address Length: %2.2x\n", arpHdr->ar_pln);
  fprintf(stdout, "ARP operation: %4.4x\n", ntohs(arpHdr->ar_op));

  printf("Sender Hardware Address: ");
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
	fprintf(stdout, "%2.2x", arpHdr->ar_sha[i]);
  } printf("\n");

  printf("Target Hardware Address: ");
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
	fprintf(stdout, "%2.2x", arpHdr->ar_tha[i]);
  } printf("\n");

  ar_ip.s_addr = arpHdr->ar_sip;
  fprintf(stdout, "Sender IP Address: %s\n", inet_ntoa(ar_ip));
  ar_ip.s_addr = arpHdr->ar_tip;
  fprintf(stdout, "Target IP Address: %s\n", inet_ntoa(ar_ip));
  printf("====================\n");
}









