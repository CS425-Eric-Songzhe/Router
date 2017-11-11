/*  * Authors: Eric Evans, Songzhe Zhu  
 * Date: 11/10/17  
 *  
 * Description:  
 * Handles ethernet header making and printing  
 */


#include <stdio.h>  
#include "sr_protocol.h"


// make ethernet header with fields 
void make_ethhdr(struct sr_ethernet_hdr* ethhdr, uint16_t type, uint8_t* src, uint8_t* dst){

  int i;     
  uint8_t sbuf[ETHER_ADDR_LEN], dbuf[ETHER_ADDR_LEN];      

  for (i = 0; i < ETHER_ADDR_LEN; i++) {        
    sbuf[i] = src[i];        
    dbuf[i] = dst[i];     
  }     

  ethhdr->ether_type = htons(type);
    
  for (i = 0; i < ETHER_ADDR_LEN; i++) {      
    ethhdr->ether_shost[i] = sbuf[i];     
    ethhdr->ether_dhost[i] = dbuf[i];  
  }

}


// printout ethernet header info
void print_ethhdr(struct sr_ethernet_hdr* ethhdr){
      
  printf("---- ETHERNET HEADER ----\n");     
  
  int i = 0;

  printf("Dest Eth Addr: "); 
  for (i = 0; i < ETHER_ADDR_LEN; i++) {   
    printf("%2.2x", ethhdr->ether_dhost[i]); 
  } 
  printf("\n");      
  
  printf("Src Eth Addr: ");  
  for (i = 0; i < ETHER_ADDR_LEN; i++) {         
    printf("%2.2x", ethhdr->ether_shost[i]);
  } 
  printf("\n");   

  printf("Pkt Type: %4.4x\n", ntohs(ethhdr->ether_type));
}
