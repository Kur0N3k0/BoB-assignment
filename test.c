#include <stdio.h>
#include <string.h>

#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

typedef struct ethernet{
	uint8_t dest[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
} ethernet;

typedef struct arphdr { 
	uint16_t htype;    /* Hardware Type           */ 
	uint16_t ptype;    /* Protocol Type           */ 
	uint8_t hlen;        /* Hardware Address Length */ 
	uint8_t plen;        /* Protocol Address Length */ 
	uint16_t oper;     /* Operation Code          */ 
	uint8_t sha[6];      /* Sender hardware address */ 
	uint8_t spa[4];      /* Sender IP address       */ 
	uint8_t tha[6];      /* Target hardware address */ 
	uint8_t tpa[4];      /* Target IP address       */ 
}arphdr_t; 

typedef struct ip{
	uint8_t hdr_len:4;
	uint8_t version:4;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint8_t ip_frag_offset:5;
	uint8_t ip_more_fragment:1;
	uint8_t ip_dont_fragment:1;
	uint8_t ip_reserved_zero:1;
	uint8_t ip_frag_offset1;
	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint16_t ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
} ip;

typedef struct tcp{
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence;
	uint32_t acknowledge;
	uint8_t ns:1;
	uint8_t reserved_part1:3;
	uint8_t data_offset:4;
	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t ecn:1;
	uint8_t cwr:1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} tcp;

#define ARP_REQUEST	1
#define ARP_REPLY	2

#define MAC_SIZE	6

typedef struct arp_packet {
	ethernet ether;
	arphdr_t arp;
} arp_packet;

int main(int argc, char *argv[]){
	arp_packet packet;

	// 0,0Ch,0Fh,14h,15h,17
	memcpy(packet.ether.dest, "\x00\x0c\x0f\x14\x15\x17", MAC_SIZE);
	memcpy(packet.ether.src , "\xff\xff\xff\xff\xff\xff", MAC_SIZE);
	packet.ether.type = htons(ETHERTYPE_ARP);

	/*
	   typedef struct arphdr {
 		    uint16_t htype;
			uint16_t ptype;
			uint8_t hlen; 
			uint8_t plen; 
			uint16_t oper;          
			uint8_t sha[6];
			uint8_t spa[4];
			uint8_t tha[6];
			uint8_t tpa[4];
		}arphdr_t;
	 */

	packet.arp.htype = htons(1);
	packet.arp.ptype = htons(ETHERTYPE_IP);
	packet.arp.hlen = 6;
	packet.arp.plen = 4;
	packet.arp.oper = htons(ARP_REQUEST);

	memcpy(packet.arp.sha, packet.ether.src, ETHER_ADDR_LEN);
	memcpy(packet.arp.spa, "\x95\x05\x95\x05", 4);
	memset(packet.arp.tha, 0x00, ETHER_ADDR_LEN);
	memcpy(packet.arp.tpa, "\x00\x00\x00\x00", 4);

	FILE *fp = fopen("./packet.pcap", "wb");

	fwrite(&packet, 1, sizeof(packet), fp);

	fclose(fp);

	return 0;
}
