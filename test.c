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

typedef struct iphdr
{
	uint32_t ihl : 4;
	uint32_t version : 4;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
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

#pragma pack(push, 1)
typedef struct packet {
	ethernet ether;
	ip iph;
	tcp tcph;
} _packet;
#pragma pack(pop)

#define CLASS_CREATE 520
#define CLASS_DELETE 514
#define CLASS_TRIGER 512
#define CLASS_NOPNOP 9505

uint8_t *inter_destmac[6] = { "\x00\x0c\x0f\x14\x15\x17", "\x3c\x14\x1f\x00\x41\x42", "\xfc\xf0\x1f\x47\x44\x08" };
uint32_t inter_destaddr[3] = { 0x64008080, 0x1f1e8080, 0x65648080 };
uint32_t inter_destport[3] = { CLASS_NOPNOP, CLASS_DELETE, CLASS_CREATE };
uint8_t *inter_filename[3] = { "inter0.pcap\x00", "inter1.pcap\x00", "inter2.pcap\x00" };

typedef struct interface {
	uint8_t  dest_mac[MAC_SIZE];
	uint32_t dest_addr;
	uint32_t dest_port;
}interface;

int main(int argc, char *argv[]){
	_packet packet;

	interface inter[3];

	for(int i = 0; i < 3; i++){
		memcpy(inter[i].dest_mac, inter_destmac[i], MAC_SIZE);
		inter[i].dest_addr = inter_destaddr[i];
		inter[i].dest_port = inter_destport[i];

		memcpy(packet.ether.dest, inter[i].dest_mac, MAC_SIZE);
		memcpy(packet.ether.src, "\xff\xff\xff\xff\xff\xff", MAC_SIZE);
		packet.ether.type = htons(ETHERTYPE_IP);

		packet.iph.daddr = inter[i].dest_addr;
		packet.iph.saddr = inter[i].dest_addr;
		packet.tcph.dest_port = htons(inter[i].dest_port);
	
		FILE *fp = fopen(inter_filename[i], "wb");
		fwrite(&packet, 1, sizeof(packet), fp);
		fclose(fp);
	}

	return 0;
}
