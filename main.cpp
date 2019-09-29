#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define PROTOCOL_TCP 0x06

uint32_t min(uint32_t x, uint32_t y) {
	if (x > y) return y;
	else return x;
}

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* packet, int pos) {
	for(int i = 0; i < 6; i++) {
		char addr = *(packet + pos + i);
		printf("%02x", (uint8_t)addr);
		if(i != 5) printf(":");
	}
}

void print_ip(const u_char* packet, int pos) {
	for(int i = 0; i < 4; i++) {
		char addr = *(packet + pos + i);
		printf("%u", (uint8_t)addr);
		if(i != 3) printf(".");
	}
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
		const uint32_t ethlen = 14;
		printf("\n<Ethernet Header>");
		// Print Source MAC Addr
		printf("\nSrc MAC: ");
		print_mac(packet, 6);
		// Print Destination MAC Addr
		printf("\nDst MAC: ");
		print_mac(packet, 0);
		// Check if IPv4
		uint16_t *ethtype = (uint16_t*)(packet + 12);
		if(ntohs(*ethtype) != ETHERTYPE_IP) {
			printf("\n[-] Not IPv4");
			continue;
		}
	
		// Analyze IP Header
		uint32_t iplen = ((*(uint8_t*)(packet + ethlen)) & 0x0F) * 4;
		uint16_t totlen = ntohs(*(uint16_t*)(packet + ethlen + 2));
		printf("\n<IPv4 Header>");
		// Print Source IP Addr
		printf("\nSrc IP: ");
		print_ip(packet, ethlen + 12);
		// Print Destination IP Addr
		printf("\nDst IP: ");
		print_ip(packet, ethlen + 16);
		// Check if TCP
		uint8_t *prot = (uint8_t*)(packet + ethlen + 9);
		if((*prot) != PROTOCOL_TCP) 
		{
			printf("\n[-] Not TCP");
			continue;
		}

		// Analyze TCP Header
		uint32_t tcplen = (((*(uint8_t*)(packet + ethlen + iplen + 12)) & 0xF0) >> 4) * 4;	
		printf("\n<TCP Header>");
		// Print Source Port #
		uint16_t *port = (uint16_t*)(packet + ethlen + iplen);
		printf("\nSrc Port: %d", ntohs(*port));
		// Print Destination Port #
		port = (uint16_t*)(packet + ethlen + iplen + 2);
		printf("\nDst Port: %d", ntohs(*port));

		// Print Data
		if(totlen == iplen + tcplen) 
			printf("\n[-] No Data");
		else {
			printf("\n<Packet Data>\n");
			int cnt = min(32, totlen - iplen - tcplen);
			for(int i = 0; i < cnt; i++) {
				printf("0x%02x ", *(uint8_t*)(packet + ethlen + iplen + tcplen + i));
			}
		}
 	}

 	pcap_close(handle);
 	return 0;
}
