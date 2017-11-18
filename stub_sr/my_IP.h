#ifndef MY_IP_H
#define MY_IP_H

#include <netinet/in.h>
#include <stdint.h>

#include "sr_protocol.h"

void handleIp(struct sr_instance*, uint8_t*, unsigned int, char* );
void makeip(struct ip*, unsigned int, uint16_t, unsigned char, unsigned char, uint32_t, uint32_t );
void ipDumpHeader(struct ip* );

#endif
