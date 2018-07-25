#pragma once

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_ARP 0x0806
#define ETHER_SIZE 14
#define PROTO_TYPE_TCP 0x06

struct Ethernet_header {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    short ether_type;
};

struct IP_header{
    unsigned char header_len:4;
    unsigned char ver:4;
    unsigned char tos;
    unsigned short total_len;
    unsigned short identifier;
    unsigned short fragment;
    unsigned char ttl;
    unsigned char protocol_id;
    unsigned short header_checksum;
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
};

struct TCP_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char seq_num[4];
    unsigned char ack_num[4];
    unsigned char test1:4;
    unsigned char hlen:4;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

struct Ethernet_header *eth_hdr;
struct IP_header *ip_hdr;
struct TCP_header *tcp_hdr;
