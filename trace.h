#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "checksum.h"

#define ETH_SIZE 14
#define MAC_LEN 6
#define IP_SIZE 20
#define TCP_SIZE 20
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_FIN 0x01
#define PSEUDO_SIZE 12
#define JUNK 6
#define MULT 4

struct eth_header{
   uint8_t dest[MAC_LEN];
   uint8_t sour[MAC_LEN];
   uint16_t type;
}__attribute__((packed));

struct arp_header{
   uint8_t junk[JUNK];
   uint16_t opcode;
   uint8_t senderMAC[MAC_LEN];
   struct in_addr senderIP;
   uint8_t targetMAC[MAC_LEN];
   struct in_addr targetIP;
}__attribute__((packed));

struct ip_header{
   uint8_t len;
   uint8_t TOS;
   uint16_t totLen;
   uint32_t junk;
   uint8_t TTL;
   uint8_t prot;
   uint16_t cksum;
   struct in_addr senderIP;
   struct in_addr destIP;
}__attribute__((packed));

struct tcp_header{
   uint16_t sour;
   uint16_t dest;
   uint32_t seq;
   uint32_t ack;
   uint16_t flag;
   uint16_t winSize;
   uint16_t cksum;
}__attribute__((packed));

struct pseudo_header{
   struct in_addr senderIP;
   struct in_addr destIP;
   uint8_t zero;
   uint8_t prot;
   uint16_t len;
}__attribute__((packed));

struct icmp_header{
   uint8_t type;
}__attribute__((packed));

struct udp_header{
   uint16_t sour;
   uint16_t dest;
}__attribute__((packed));

void eth_layer(const u_char *data);
void arp_layer(const u_char *data);
void ip_layer(const u_char *data);
void tcp_layer(const u_char *data, struct ip_header *ip);
void icmp_layer(const u_char *data, int len);
void udp_layer(const u_char *data);
void check_port(int port);
struct pseudo_header *init_pseudo(struct ip_header *ip);
