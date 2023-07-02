#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <stdbool.h>

#define PCAP_FILE "example_org_http.pcapng"
#define ALERT_FILE "alerts.txt"
#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip {
  u_char ip_vhl; /* version << 4 | header length >> 2 */
  u_char ip_tos; /* type of service */
  u_short ip_len; /* total length */
  u_short ip_id; /* identificator */
  u_short ip_off; /* field fragment offset */
  #define IP_RF 0x8000 /* reserved fragment flag */
  #define IP_DF 0x4000 /* dont fragment flag */
  #define IP_MF 0x2000 /* more fragment flag */
  #define IP_OFFMASK 0x1fff /* mask for bits of the fragment */
  u_char ip_ttl; /* time of life */
  u_char ip_p; /* Protocol */
  u_short ip_sum; /* checksum */
  // struct in_addr bination of ip_src,ip_dst; /* source address and destination address */
  struct in_addr ip_src;
  struct in_addr ip_dst;
};

/* TCP header */
struct tcp {
  u_short th_sport;   /* source port */
  u_short th_dport;   /* destination port */
  u_int32_t th_seq;       /* sequence number */
  u_int32_t th_ack;       /* acknowledgement number */
  u_char th_offx2;    /* data offset, rsvd */
  u_char th_flags;
  u_short th_win;     /* window */
  u_short th_sum;     /* checksum */
  u_short th_urp;     /* urgent pointer */
};

void raise_alerts(char *src, char *dst, u_short srcport, u_short dstport){
  char alert_src[100], alert_dst[100], alert_msg[100];
  u_short alert_srcport, alert_dstport;

  FILE *in_file = fopen(ALERT_FILE, "r");
  if (in_file == NULL){
    printf("Could not open file\n"); 
    exit(-1);
  }

  while (!feof(in_file)){
    fscanf(in_file, "%s %hu %s %hu %s", &alert_src, &alert_srcport, &alert_dst, &alert_dstport, &alert_msg);
    if ( (!strcmp(src, alert_src)) && (!strcmp(dst, alert_dst)) && (srcport == alert_srcport) && (dstport == alert_dstport) ){
      printf("%s\n", alert_msg);
      return;
    }
  }
}

void packetHandler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet){
  char src[100], dst[100];
  u_short srcport, dstport;
  struct ethernet *ethernet = (struct ethernet *) packet;
  struct ip *ip = (struct ip *) (packet + sizeof *ethernet + 2);
  struct tcp *tcp = (struct tcp *) (packet + sizeof *ethernet + sizeof *ip + 2);
  
  strcpy(src, inet_ntoa(ip->ip_src));
  strcpy(dst, inet_ntoa(ip->ip_dst));
  srcport = ntohs(tcp->th_sport);
  dstport = ntohs(tcp->th_dport);

  raise_alerts(src, dst, srcport, dstport);
}
