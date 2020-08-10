import socket
import struct
# from getmac import get_mac_address as get_mac_addr
import textwrap
import binascii
import time

def udp(raw_data):
    (src_port,des_port,length,checksum) = struct.unpack('H H H H', raw_data[:8])
    data = raw_data[8:]
    return [src_port,des_port,length,checksum,data]

class ICMPPacket:
        def __init__(self , src_add , des_add ,icmp_type = 0,icmp_code = 0,icmp_chks = 0,icmp_id   = 1,icmp_seq  = 1,data ='' ,):
        #IP header
        self.version = 4
        self.IHL = 5
        self.verionanihl = (self.version << 4) + self.IHL
        self.DSPC = 0
        self.ECN = 0
        self.total_length = 40 #must change based on transmission nob
        self.identification = 0
        self.flag = 0 #nob
        self.fragmentatoin = 0
        self.TTL = 200
        self.protocol = 6 #must change based on transmission
        self.checksum = 0 #must change
        self.src_ip = src_add
        self.des_ip = des_add
        self.ip_header = struct.pack('!BBHHHBBH4s4s',self.verionanihl,self.DSPC,self.total_length,self.identification,self.flag,self.TTL,self.protocol,
        self.checksum,self.src_ip,self.des_ip)
        #icmp header

        self.icmp_type = icmp_type#eco response 
        self.icmp_code = icmp_code
        self.icmp_chks = icmp_chks
        self.icmp_id   = icmp_id
        self.icmp_seq  = icmp_seq
        self.data      = data
        self.raw = None
        self.create_icmp_field()
    def create_icmp_field(self):
        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )

        # calculate checksum
        self.icmp_chks = self.chksum(self.raw+self.data)

        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )
       self.finally_pack = self.ip_header + self.raw

        return 

    def chksum(self, msg):
        s = 0       # Binary Sum

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):

            a = ord(msg[i]) 
            b = ord(msg[i+1])
            s = s + (a+(b << 8))
            
        
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff

        return s


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
    _raw_data = raw_data[24:]
    str_out = ''
    while(True):
        (numb,) = struct.unpack('H',_raw_data[:2])
        if numb == 0:
            break
        _raw_data = _raw_data[2:]
        for i in numb:
            (_str,) = struct.unpack('2s',_raw_data[:2])
            str_out = str_out + _str + '.'
            raw_data = raw_data[:2] 
        (QTYPE,QCLASS) = struct.unpack('I I', raw_data[19:21])
    return [ID,QR,OPCODE,AA,TC,RD,RA,Z,RCODE,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT,str_out,QTYPE,QCLASS]


class DNS_maker:
    def __init__(self,DNS_Question,udp_header,IP_header,wirefile):
         #IP header
        self.version = 4
        self.IHL = 5
        self.verionanihl = (self.version << 4) + self.IHL
        self.DSPC = 0
        self.ECN = 0
        self.total_length = 56 #must change based on transmission nob
        self.identification = 0
        self.flag = 0 #nob
        self.fragmentatoin = 0
        self.TTL = 200
        self.protocol = 17 #must change based on transmission
        self.checksum = 0 #must change
        self.src_ip = socket.inet_aton(IP_header[5])
        self.des_ip = socket.inet_aton(IP_header[4])
        self.ip_header = struct.pack('!BBHHHBBH4s4s',self.verionanihl,self.DSPC,self.total_length,self.identification,self.flag,self.TTL,self.protocol,
        self.checksum,self.src_ip,self.des_ip)
        #udp 
        self.src_port = udp_header[1]
        self.des_port = udp_header[0]
        self.length = udp_header[2]
        self.checksum = 0 #optional in ipv4
        self.udp_header = struct.pack('H H H H',src_port,des_port,length,checksum )
        #dns
        self.ID = DNS_Question[0]
        self.QR = 1
        self.OPCODE = DNS_Question[2]
        self.AA = DNS_Question[3]
        self.TC = DNS_Question[4]
        self.RD = DNS_Question[5]
        self.RA = DNS_Question[6]
        self.Z = DNS_Question[7]
        self.RCODE = DNS_Question[8]
        self.QDCOUNT = DNS_Question[9]
        self.ANCOUNT = DNS_Question[10]
        self.NSCOUNT = DNS_Question[11]
        self.ARCOUNT = DNS_Question[12]
        self.dns_header = struct.pack('I s B s s s s 3s B H H H H',ID,QR,OPCODE,AA,TC,RD,RA,Z,RCODE,QDCOUNT,
        ANCOUNT,NSCOUNT,ARCOUNT)
        #dns question
        # self.str_out = DNS_Question[13]
        # self.QTYPE = DNS_Question[14]
        # self.QCLASS = DNS_Question[15]
        #alternate
        self.dnsquestion = udp_header[24:44]
        #dns Answer
        self.Name = DNS_Question[13]
        self.type = 1
        self.Class = 1
        self.ttl = 200
        self.RDlength = len(dictio[DNS_Question[13]])
        self.RData = dictio[DNS_Question[13]]
        self.dns_answer = struct.packet('64s I I 32s I I',self.Name,self.type,self.Class,self.ttl,self.RDlength,self.RData)
        self.dns_sender = self.ip_header + self.udp_header + self.dns_header + self.dns_answer
        s = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket.IPPROTO_RAW)
        s.sendto(self.dns_sender , (self.des_ip , 0 ))
        wirefile.write(self.dns_sender)

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
        
def icmp_ans(data , des_add , src_add,wirefile):
    s = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket.IPPROTO_RAW)
    packet = ICMPPacket(src_add , des_add )
    wirefile.write(packet)
    s.sendto(packet.finally_pack , (des_add , 0 ))
    
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    wirefile = pcap('wirecap')
    while(True):
        raw_data, addr = conn.recvfrom(65536)
        ether_header = ether(raw_data)
        #arp 
        if hex(ether_header[2]) == 0x0806: 
            arp_header = arp(ether_header[-1])
        else:
            ip_header = ipv4(ether_header[-1])
        #icmp 
            if ip_header[3] == 1:
                icmp_header = icmp(ip_header[-1])   
                icmp_ans(ip_header[-1], ip_header[4] , ip_header[5],wirefile)
            elif ip_header[3] == 17:
                udp_header = udp(ip_header[-1])
                if (udp_header[1] = 57):
                    dns = DNS(udp_header[-1])
                    dns_out = DNS_maker(udp_header[-3],udp_header,ip_header,wirefile )

