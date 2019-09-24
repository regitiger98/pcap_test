#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

	printf("\n\n[+] %u bytes captured", header->caplen);
	
	// Analyze Ethernet Header
	uint32_t ethlen = 14;
	printf("\n<Ethernet Header>");
	// Print Source MAC Addr
	printf("\nSrc MAC: ");
	for(int i = 0; i < 6; i++)
	{
		char addr = *(packet + 6 + i);
		printf("%02x", (uint8_t)addr);
		if(i != 5) printf(":");
	}
	// Print Destination MAC Addr
	printf("\nDst MAC: ");
	for(int i = 0; i < 6; i++)
	{
		char addr = *(packet + i);
		printf("%02x", (uint8_t)addr);
		if(i != 5) printf(":");
	}
	// Check if IPv4
	uint16_t *ipv4 = (uint16_t*)(packet + 12);
	if(ntohs(*ipv4) != 0x0800)
	{
		printf("\n[-] Not IPv4");
		continue;
	}
	
	// Analyze IP Header
	uint32_t iplen = ((*(uint8_t*)(packet + ethlen)) % 16) * 4;
	printf("\n<IPv4 Header>");
	// Print Source IP Addr
	printf("\nSrc IP: ");
	for(int i = 0; i < 4; i++)
	{
		char addr = *(packet + ethlen + 12 + i);
		printf("%u", (uint8_t)addr);
		if(i != 3) printf(".");
	}
	// Print Destination IP Addr
	printf("\nDst IP: ");
	for(int i = 0; i < 4; i++)
	{
		char addr = *(packet + ethlen + 16 + i);
		printf("%u", (uint8_t)addr);
		if(i != 3) printf(".");
	}
	// Check if TCP
	uint8_t *tcp = (uint8_t*)(packet + ethlen + 9);
	if((*tcp) != 6) 
	{
		printf("\n[-] Not TCP");
		continue;
	}

	// Analyze TCP Header
	uint32_t tcplen = ((*(uint8_t*)(packet + ethlen + iplen + 12)) / 16) * 4;	
	printf("\n<TCP Header>");
	// Print Source Port #
	uint16_t *port = (uint16_t*)(packet + ethlen + iplen);
	printf("\nSrc Port: %d", ntohs(*port));
	// Print Destination Port #
	port = (uint16_t*)(packet + ethlen + iplen + 2);
	printf("\nDst Port: %d", ntohs(*port));

	// Print Data
	uint32_t hlen = ethlen + iplen + tcplen;
	if((header->caplen <= hlen) || *(packet + hlen) == 0) 
		printf("\n[-] No Data");
	else
	{
		printf("\n<Packet Data>");
		printf("\n%s", packet + 54);
	}
  }

  pcap_close(handle);
  return 0;
}
