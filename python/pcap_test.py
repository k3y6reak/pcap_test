import socket
import struct
import binascii

ETHER_HDR_SIZE = 14
IP_HDR_MIN_SIZE = 20
ETHER_TYPE_IPv4 = 0x0800
TCP_HDR_MIN_SIZE = 20

def TCP_Header(tcp_hdr):
    tcp_hdr = struct.unpack('!HHLLBBHHH', tcp_hdr)
    src_port = tcp_hdr[0]
    dst_port = tcp_hdr[1]
    seq_num = tcp_hdr[2]
    ack_num = tcp_hdr[3]
    hdr_len = ((tcp_hdr[4] & 0xF0) >> 4)*4
    #offset_reserved = (tcp_hdr[4] & 0x0F)
    tcp_flag = tcp_hdr[5]
    window = tcp_hdr[6]
    checksum = tcp_hdr[7]
    urgent_pointer = tcp_hdr[8]

    print "Destination Port: ", dst_port
    print "Source Port: ", src_port
    print "TCP Header Len: ", hdr_len
    return hdr_len

def IP_Header(ip_hdr):
    ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_hdr)
    version = (ip_hdr[0] & 0xF0) >> 4 # B = 1byte
    hdr_len = (ip_hdr[0] & 0x0F)*4
    tos = ip_hdr[1] # B = 1byte
    total_len = ip_hdr[2] # H = 2 byte
    identification = ip_hdr[3]
    fragment = ip_hdr[4]
    ttl = ip_hdr[5]
    protocol = ip_hdr[6]
    checksum = ip_hdr[6]
    src_ip = socket.inet_ntoa(ip_hdr[8]) # 4s = 4byte
    dst_ip = socket.inet_ntoa(ip_hdr[9])

    print "Version: ", version,
    if version == 4:
        print "(IPv4)"
    if version == 6:
        print "(IPv6)"
    print "IP Header len: ", hdr_len
    print "Destination IP: ", dst_ip
    print "Source IP", src_ip
    print "Protocol: ", protocol,
    if protocol == 6:
        print "(TCP)"

    return total_len, hdr_len

def Ethernet_Header(ether_hdr):
    ether_hdr = struct.unpack("!6s6s2s", ether_hdr)
    dst_mac = binascii.hexlify(ether_hdr[0]) #6s = 6bytes
    src_mac = binascii.hexlify(ether_hdr[1]) #6s = 6bytes
    proto_type = binascii.hexlify(ether_hdr[2]) #2s = 2bytes

    print "================================"
    print "Destination MAC: ", dst_mac
    print "Source MAC: ", src_mac
    print "Type", proto_type

def main():
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(ETHER_TYPE_IPv4))

    while True:
        packet = s.recvfrom(65565)[0]
        ether_hdr = packet[0:ETHER_HDR_SIZE]
        Ethernet_Header(ether_hdr)
        ip_hdr = packet[ETHER_HDR_SIZE:ETHER_HDR_SIZE+IP_HDR_MIN_SIZE]
        total_len, ip_hdr_len = IP_Header(ip_hdr)
        tcp_hdr = packet[ETHER_HDR_SIZE+IP_HDR_MIN_SIZE:ETHER_HDR_SIZE+ip_hdr_len+TCP_HDR_MIN_SIZE]
        tcp_hdr_len = TCP_Header(tcp_hdr)

        break_idx = 0
        print "DATA: ",
        for data in packet[ETHER_HDR_SIZE+ip_hdr_len+tcp_hdr_len:] :
            print binascii.hexlify(data), " ",

            if break_idx == 16:
                break
            break_idx += 1
        print "\n"

if __name__ == '__main__':
    main()
