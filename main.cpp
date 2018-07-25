#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "net_hdr.h"
#include "byte_order.h"

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
    //printf("%u bytes captured\n", header->caplen);
    eth_hdr = (struct Ethernet_header*)packet;

    printf("=====================================\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x \n", eth_hdr->dst_mac[0], eth_hdr->dst_mac[1], eth_hdr->dst_mac[2], eth_hdr->dst_mac[3], eth_hdr->dst_mac[4], eth_hdr->dst_mac[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x \n", eth_hdr->src_mac[0], eth_hdr->src_mac[1], eth_hdr->src_mac[2], eth_hdr->src_mac[3], eth_hdr->src_mac[4], eth_hdr->src_mac[5]);
    printf("Type: %d\n", eth_hdr->ether_type);


    if(byte2_order(eth_hdr->ether_type) == ETHER_TYPE_IPv4)
    {
        ip_hdr = (struct IP_header*)(packet+ETHER_SIZE);
        printf("header_len: %d\n", ip_hdr->header_len*4);
        printf("Version: %d\n", ip_hdr->ver);
        printf("TOS: %02x\n", ip_hdr->tos);
        printf("Total_len: %d\n", ip_hdr->total_len);
        printf("Identifier: %02x\n", ip_hdr->identifier);
        printf("Fragment: %02x\n", ip_hdr->fragment);
        printf("TTL: %d\n", ip_hdr->ttl);
        printf("Protocol_ID: %d\n", ip_hdr->protocol_id);
        printf("Chksum: %d\n", ip_hdr->header_checksum);
        printf("src_ip: %d:%d:%d:%d\n", ip_hdr->src_ip[0], ip_hdr->src_ip[1], ip_hdr->src_ip[2], ip_hdr->src_ip[3]);
        printf("dst_ip: %d:%d:%d:%d\n", ip_hdr->dst_ip[0], ip_hdr->dst_ip[1], ip_hdr->dst_ip[2], ip_hdr->dst_ip[3]);

        if(ip_hdr->protocol_id == PROTO_TYPE_TCP)
        {
            tcp_hdr = (struct TCP_header*)(packet+ETHER_SIZE+(ip_hdr->header_len*4));
            printf("Src Port: %d\n", byte2_order(tcp_hdr->src_port));
            printf("Dst Port: %d\n", byte2_order(tcp_hdr->dst_port));
            printf("HLEN: %d\n", tcp_hdr->hlen*4);

            int break_idx = 0;
            int i = ETHER_SIZE+(ip_hdr->header_len*4) + (tcp_hdr->hlen*4);
            for(i; i < ip_hdr->total_len; i++)
            {
                printf("%02x ", packet[i]);
                if(break_idx == 16)
                {
                    break;
                }
                break_idx++;
            }

            printf("\n");

        }
    }

  }

  pcap_close(handle);
  return 0;
}
