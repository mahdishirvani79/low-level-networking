
import socket
import struct
import getmac
# from getmac import get_mac_address as get_mac_addr
import textwrap
import binascii
import time


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def ether(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return [get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]]


def ipv4(raw_data): 
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    return [version, header_length, ttl, proto, toipv4(src), toipv4(target), data]

def toipv4(addr):
    return '.'.join(map(str,addr))

def icmp(data):
    tpe,code,checksum = struct.unpack('!BBH',data[:4])
    return [tpe,code, hex(checksum), repr(data[4:])]

def tcp(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14]) 
    offset = (offset_reserved_flags >> 12) * 4 
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return [src_port, dest_port, sequence, acknowledgment, urg, ack,
    psh, rst, syn, fin, data]

def udp(raw_data):
    (src_port,des_port,length,checksum) = struct.unpack('H H H H', raw_data[:8])
    data = raw_data[8:]
    return [src_port,des_port,length,checksum,data]

def DNS(raw_data):
    (ID,QR_f,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT) = struct.unpack('I I I I I I', raw_data[:24])
    QR = QR_f & 1
    OPCODE = (QR_f & 30) >> 1
    AA = (QR_f & 32) >> 5
    TC = (QR_f & 64) >> 6
    RD = (QR_f & 128) >> 7
    RA = (QR_f & 256) >> 8
    Z = (QR_f & 3584) >> 9
    RCODE = (QR_f & 61440) >> 12
    return [ID,QR,OPCODE,AA,TC,RD,RA,Z,RCODE]


def arp(packet):

    (a ,b ,c ,d ,e ,f ,g ,h ,i ) = struct.unpack('2s2s1s1s2s6s4s6s4s',packet[:28])
    hw_type=(binascii.hexlify(a)).decode('utf-8')
    proto_type=(binascii.hexlify(b)).decode('utf-8')
    hw_size=(binascii.hexlify(c)).decode('utf-8')
    proto_size=(binascii.hexlify(d)).decode('utf-8')
    opcode=(binascii.hexlify(e)).decode('utf-8')
    return [hw_type,proto_type,hw_size,proto_size,opcode,socket.inet_ntoa(g),socket.inet_ntoa(i)]


def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

class pcap:

    def __init__(self, file_name, link_type=1):
        self.pcap_file = open(file_name, 'wb')
        self.pcap_file.write(struct.pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        lengh = len(data)
        self.pcap_file.write(struct.pack('@IIII', ts_sec, ts_usec, lengh, lengh))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    wirefile = pcap('wirecap')
    while(True):
        raw_data, addr = conn.recvfrom(65536)
        ether_header = ether(raw_data)
        wirefile.write(raw_data)
        print('\n Ethernet Frame: ')
        print('\t - ' + 'Destination: {}, Source: {}, Protocol: {}'.format(ether_header[0], ether_header[1], ether_header[2]))  
        if hex(ether_header[2]) == 0x0806: 
            arp_header = arp(ether_header[-1])
            wirefile.write(ether_header[-1])
            print('\n arp Frame:' )
            print('\t -' + 'hw_type: {},proto_type: {},hw_size: {},proto_size: {},opcode: {}'.format(arp_header[0], arp_header[1],
            arp_header[2], arp_header[3], arp_header[4]))
        else:
            ip_header = ipv4(ether_header[-1])
            wirefile.write(ether_header[-1])
            print('\n ipv4 Frame: ')
            print('\t - ' + 'version: {}, destination: {}, ttl: {}, proto: {}, src: {}, target: {}'.format(ip_header[0]
            , ip_header[1], ip_header[2], ip_header[3], ip_header[4], ip_header[5])) 
        #icmp 
            if ip_header[3] == 1:
                icmp_header = icmp(ip_header[-1])
                wirefile.write(ip_header[-1])
                print('\t - ' + 'ICMP Packet:')
                print('\t\t - ' + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_header[0], icmp_header[1], icmp_header[2]))
                print('\t\t - '+ 'ICMP Data:')
                print(format_output_line('\t\t\t', icmp_header[-1])) 
                break   
        #tcp   
            elif ip_header[3] == 6:
                tcp_header = tcp(ip_header[-1])
                wirefile.write(ip_header[-1])
                print('\t - ' + 'TCP Segment:')
                print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp_header[0], tcp_header[1]))
                print('\t\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(tcp_header[2], tcp_header[3]))
                print('\t\t - ' + 'Flags:')
                print('\t\t\t - ' + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_header[4], tcp_header[5], tcp_header[6]))
                print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp_header[7], tcp_header[8], tcp_header[9]))
            

                if len(tcp_header[-1]) > 0:
                    #DNS
                    if tcp_header[0] == 53 or tcp_header[1] == 53:
                        DNS_header = DNS(tcp_header[-1])
                        wirefile.write(tcp_header[-1])
                        print('\t\t ID: {},QR: {},OPCODE: {},AA: {},TC: {},RD: {},RA: {},Z: {},RCODE: {}'.format(DNS_header[0], DNS_header[1],
                        DNS_header[2], DNS_header[3], DNS_header[4], DNS_header[5],DNS_header[6],DNS_header[7],DNS_header[8] ))
                        #HTTP           
                    elif tcp_header[0] == 80 or tcp_header[1] == 80:
                        
                        wirefile.write(tcp_header[-1])
                        print('\t\t- '+ 'HTTP Data:')
                        try:
                            http = tcp_header[-1].decode('utf-8')
                            http_info = str(http).split('\n')
                            for line in http_info:
                                print('\t\t\t ' + str(line))
                        except:
                            print(format_output_line('\t\t\t', tcp_header[-1]))
                    else:
                        print('\t\t' + 'TCP Data:')
                        print(format_output_line('\t\t\t', tcp_header[-1]))
                                  

        #udp
            elif ip_header[3] == 17:
                udp_header = udp(ip_header[-1])
                wirefile.write(ip_header[-1])
                print('\t' + 'UDP Segment:')
                print('\t\t' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_header[0], udp_header[1], udp_header[2]))
                if udp_header[0] == 53 or udp_header[1] == 53:
                    DNS_header = DNS(tcp_header[-1])
                    wirefile.write(tcp_header[-1])
                    print('\t\t ID: {},QR: {},OPCODE: {},AA: {},TC: {},RD: {},RA: {},Z: {},RCODE: {}'.format(DNS_header[0], DNS_header[1],
                    DNS_header[2], DNS_header[3], DNS_header[4], DNS_header[5],DNS_header[6],DNS_header[7],DNS_header[8]))
                    
    wirefile.close()        
            
main()