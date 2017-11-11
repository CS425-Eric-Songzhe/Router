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
