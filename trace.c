#include "trace.h"

void eth_layer(const u_char *data) {

   struct eth_header *eth;

   eth = (struct eth_header *)data;
   printf("\tEthernet Header\n");
      printf("\t\tDest MAC: %s\n", ether_ntoa((const struct ether_addr *)&(eth->dest)));
      printf("\t\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)&(eth->sour)));
      switch (htons(eth->type)) {
         case 0x0806:
            printf("\t\tType: ARP\n");
            arp_layer(data);
            break;
         case 0x0800:
            printf("\t\tType: IP\n");
            ip_layer(data);
            break;
         default:
            printf("\t\tType: Unkown\n");
            break;
      }
}

void arp_layer(const u_char *data) {

   struct arp_header *arp;

   data+=ETH_SIZE;
   arp = (struct arp_header *)data;
   printf("\n\tARP header\n");
   if (htons(arp->opcode) == 0x0001) {
      printf("\t\tOpcode: Request\n");
   } else {
      printf("\t\tOpcode: Reply\n");
   }
   printf("\t\tSender MAC: %s\n", ether_ntoa((const struct ether_addr *)&(arp->senderMAC)));
   printf("\t\tSender IP: %s\n", inet_ntoa(arp->senderIP));
   printf("\t\tTarget MAC: %s\n", ether_ntoa((const struct ether_addr *)&(arp->targetMAC)));
   // random extra newline
   printf("\t\tTarget IP: %s\n\n", inet_ntoa(arp->targetIP));
}

void ip_layer(const u_char *data) {

   struct ip_header *ip;
   
   data+=ETH_SIZE;
   ip = (struct ip_header *)data;
   printf("\n\tIP Header\n");
   printf("\t\tTOS: 0x%x\n", ip->TOS);
   printf("\t\tTTL: %d\n", ip->TTL);
   switch (ip->prot) {
      case 0x01:
         printf("\t\tProtocol: ICMP\n");
         break;
      case 0x06:
         printf("\t\tProtocol: TCP\n");
         break;
      case 0x11:
         printf("\t\tProtocol: UDP\n");
         break;
      default:
         printf("\t\tProtocol: Unknown\n");
         break;
   }
   if (in_cksum((short unsigned int *)data, (0x0F & ip->len) * MULT)) {
      printf("\t\tChecksum: Incorrect (0x%x)\n", htons(ip->cksum));
   } else {
      printf("\t\tChecksum: Correct (0x%x)\n", htons(ip->cksum));
   }
   printf("\t\tSender IP: %s\n", inet_ntoa(ip->senderIP));
   printf("\t\tDest IP: %s\n", inet_ntoa(ip->destIP));
   switch (ip->prot) {
      case 0x01:
         icmp_layer(data, (0x0F & ip->len) * MULT);
         break;
      case 0x06:
         tcp_layer(data, ip);
         break;
      case 0x11:
         udp_layer(data);
         break;
   }
}

void tcp_layer(const u_char *data, struct ip_header *ip) {

   struct tcp_header *tcp;
   struct pseudo_header *pseudo;
   uint8_t *buffer;
   
   data+=IP_SIZE;
   tcp = (struct tcp_header *)data;
   printf("\n\tTCP Header\n");
   printf("\t\tSource Port:  ");
   check_port(htons(tcp->sour));
   printf("\t\tDest Port:  ");
   check_port(htons(tcp->dest));
   printf("\t\tSequence Number: %u\n", ntohl(tcp->seq));
   printf("\t\tACK Number: %u\n", htonl(tcp->ack));
   if (htons(tcp->flag) & TCP_SYN) {
      printf("\t\tSYN Flag: Yes\n");
   } else {
      printf("\t\tSYN Flag: No\n");
   }
   if (htons(tcp->flag) & TCP_RST) {
      printf("\t\tRST Flag: Yes\n");
   } else {
      printf("\t\tRST Flag: No\n");
   }
   if (htons(tcp->flag) & TCP_FIN) {
      printf("\t\tFIN Flag: Yes\n");
   } else {
      printf("\t\tFIN Flag: No\n");
   }
   printf("\t\tWindow Size: %d\n", htons(tcp->winSize));
   pseudo = init_pseudo(ip);
   buffer = calloc(PSEUDO_SIZE + htons(pseudo->len), 1);
   memcpy(buffer, pseudo, PSEUDO_SIZE);
   memcpy((buffer + PSEUDO_SIZE), data, htons(pseudo->len));
   if (in_cksum((short unsigned int *)buffer, htons(pseudo->len) + PSEUDO_SIZE)) {
      printf("\t\tChecksum: Incorrect (0x%x)\n", htons(tcp->cksum));
   } else {
      printf("\t\tChecksum: Correct (0x%x)\n", htons(tcp->cksum));
   }
   free(pseudo);
   free(buffer);
}

struct pseudo_header *init_pseudo(struct ip_header *ip){
   
   struct pseudo_header *pseudo = calloc(sizeof(struct pseudo_header), 1);
   
   memcpy(&(pseudo->senderIP), &(ip->senderIP), sizeof(ip->senderIP));
   memcpy(&(pseudo->destIP), &(ip->destIP), sizeof(ip->destIP));
   memcpy(&(pseudo->prot), &(ip->prot), sizeof(ip->prot));
   pseudo->len = ntohs(htons(ip->totLen) - IP_SIZE);
   
   return pseudo;
}

void icmp_layer(const u_char *data, int len) {

   struct icmp_header *icmp;
   
   if (len > IP_SIZE) {
      data+=len;
   } else {
      data+=IP_SIZE;
   }
   icmp = (struct icmp_header *)data;
   printf("\n\tICMP Header\n");
   switch (icmp->type) {
      case 0x00:
         printf("\t\tType: Reply\n");
         break;
      case 0x08:
         printf("\t\tType: Request\n");
         break;
      default:
         printf("\t\tType: Unknown\n");
         break;
   }
}

void udp_layer(const u_char *data) {

   struct udp_header *udp;
   
   data+=TCP_SIZE;
   udp = (struct udp_header *)data;
   printf("\n\tUDP Header\n");
   printf("\t\tSource Port:  ");
   check_port(htons(udp->sour));
   printf("\t\tDest Port:  ");
   check_port(htons(udp->dest));
}

void check_port(int port) {

   switch (port) {
      case 21:
         printf("FTP\n");
         break;
      case 23:
         printf("Telnet\n");
         break;
      case 25:
         printf("SMTP\n");
         break;
      case 80:
         printf("HTTP\n");
         break;
      case 110:
         printf("POP3\n");
         break;
      default:
         printf("%d\n", port);
         break;
   }
}

int main(int argc, char **argv) {

   pcap_t *fp;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct pcap_pkthdr *header;
   const u_char *pkt_data;
   int i = 0;
   
   if (argc != 2) {
      printf("usage: %s filename", argv[0]);
      return -1;
   }
   
   if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
      fprintf(stderr,"\nError opening dump file\n");
      return -1;
   }
   
   while (pcap_next_ex(fp, &header, &pkt_data) >= 0) {
      i++;
      printf("\nPacket number: %d  Packet Len: %d\n\n", i, header->len);
      eth_layer(pkt_data);
   }
   
   pcap_close(fp);
   
   return 0;
}