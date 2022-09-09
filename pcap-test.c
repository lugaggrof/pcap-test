#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool isTcp(const u_char *packet) {
  struct libnet_ethernet_hdr *h;
  h = (struct libnet_ethernet_hdr *)packet;
  uint16_t ether_type = htons(h->ether_type);


  struct libnet_ipv4_hdr *iph;
  iph = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ipv4_hdr));
  uint8_t ip_p = iph->ip_p;
  // printf("ip protocol version: %u\n", ip_p);
  return ether_type == 0x0800;
}

void readMac(const u_char *packet) {
  struct libnet_ethernet_hdr *h;
  h = (struct libnet_ethernet_hdr *)packet;

  printf("source mac: ");
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    printf("%02x", h->ether_shost[i]);
    if (i != ETHER_ADDR_LEN - 1) {
      printf(":");
    }
  }
  printf("\n");

  printf("destination mac: ");
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    printf("%02x", h->ether_dhost[i]);
    if (i != ETHER_ADDR_LEN - 1) {
      printf(":");
    }
  }
  printf("\n");
}

void readIp(const u_char *packet) {
  struct libnet_ipv4_hdr *h;
  h = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ipv4_hdr));

  printf("source ip: ");
  printf("%s\n", inet_ntoa(h->ip_src));

  printf("destination ip: ");
  printf("%s\n", inet_ntoa(h->ip_dst));
}

void readPort(const u_char *packet) {
  struct libnet_tcp_hdr *h;
  h = (struct libnet_tcp_hdr *) (packet + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_ipv4_hdr));

  printf("source port: ");
  printf("%d\n", ntohs(h->th_sport));

  printf("destination port: ");
  printf("%d\n", ntohs(h->th_dport));
}

void readData(const u_char *packet) {
  int ethernet_hdr_size = 14;
  int tcp_hdr_size = 20;
  int ipv4_hdr_size = 20;
  int packetDataOffset = ethernet_hdr_size + tcp_hdr_size + ipv4_hdr_size;
  for (int i = packetDataOffset; i < packetDataOffset + 10; i++) {
    printf("0x%02x ", packet + i);
  }
}

void readPcap(const u_char *packet) {
  bool read_packet = isTcp(packet);
  if (read_packet) {
    readMac(packet);
    readIp(packet);
    readPort(packet);
    readData(packet);
  }
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
    readPcap(packet);
		// printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}

