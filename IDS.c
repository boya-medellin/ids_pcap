#include "IDS.h"

int main(int argc,char **argv){ 
  int i;
  char *dev; 
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  /* open .pcapng file for reading */
  descr = pcap_open_offline(PCAP_FILE, errbuf);
  /* call pcap_loop */
  pcap_loop(descr,100,packetHandler,NULL);

  return 0;
}
