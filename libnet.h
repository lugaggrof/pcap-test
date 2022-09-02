#define ETHER_ADDR_LEN 0x6
#include <stdint.h>
#include <arpa/inet.h>

struct libnet_ethernet_hdr {
  uint8_t ether_dhost[ETHER_ADDR_LEN];
  uint8_t ether_shost[ETHER_ADDR_LEN];
  uint16_t ether_type;
};

struct inaddr {
	unsigned long  s_addr;
};

struct libnet_ipv4_hdr {
  uint8_t ip_hl:4, ip_v:4;
  uint8_t ip_tos;
  uint16_t ip_len;
  uint16_t ip_id;
  uint16_t ip_off;
  uint8_t ip_ttl;
  uint16_t ip_p;
  uint16_t ip_sum;
  struct in_addr ip_src, ip_dst;
};

struct libnet_tcp_hdr {
  uint16_t th_sport;
  uint16_t th_dport;
  uint32_t th_seq;
  uint32_t th_ack;
  uint8_t th_x2: 4, th_off:4;
  uint8_t th_flags;
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};

