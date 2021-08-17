from scapy.all import *
import os

class ProcessLogs:

    global directory, filenames  
    directory = "pcaps"
    filenames = []

    def dirList():
        files = []
        for filename in os.scandir(directory):
            if filename.is_file():
                files.append(filename.path)
        return sorted(files)

    if __name__ == "__main__": 
        #while True:
        filenames = dirList()
        for i in range(10):
            cap = rdpcap(filenames[i])
            for packet in cap:
                if packet.haslayer(TCP):
                    if 'dport' in packet['TCP']:
                        print(packet[TCP][dport])
                        if packet['TCP']['dport'] == 22:
                            print(packet.show())

