from scapy.all import *
from datetime import datetime

class ids:
    __flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }

    __ip_cnt_TCP = {}               #ip address requests counter

    __THRESH=1000               

    def sniffPackets(self,packet):
        if packet.haslayer(IP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

        if packet.haslayer(TCP):
            src_port=packet.sport
            dst_port=packet.dport
            print(", Port: %s --> %s, "%(src_port,dst_port), end='')
            print([type(self).__flagsTCP[x] for x in packet.sprintf('%TCP.flags%')])
            #self.detect_TCPflood(packet)
        else:
            print()


    '''
    def detect_TCPflood(self,packet):
        if packet.haslayer(TCP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

            if stream in type(self).__ip_cnt_TCP:
                type(self).__ip_cnt_TCP[stream] += 1
            else:
                type(self).__ip_cnt_TCP[stream] = 1

            for stream in type(self).__ip_cnt_TCP:
                pckts_sent = type(self).__ip_cnt_TCP[stream]
                if pckts_sent > type(self).__THRESH:
                    src = stream.split(':')[0]
                    dst = stream.split(':')[1]
                    print("Possible Flooding Attack from %s --> %s"%(src,dst))
    '''

if __name__ == '__main__':
    print("custom packet sniffer ")
    sniff(filter="ip",iface="eth0",prn=ids().sniffPackets)

