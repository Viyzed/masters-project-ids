from scapy.all import *
from scapy.layers.http import *
import os
from time import sleep

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
        
        row = {
            "username": "",
            "client_ip": "",
            "continent_code": "",
            "country_code": "",
            "time": "",
            "target_ip": "",
            "request_method": "",
            "request_url": "",
            "http_protocol": "",
            "http_response_code": "",
            "user_agent": ""
        }

        while True:
            filenames = dirList()
            if len(filenames) > 2:
                for i in range(len(filenames)):
                    requestProcessed = False
                    cap = rdpcap(filenames[i])
                    for packet in cap:
                        if HTTP in packet:
                            if HTTPRequest in packet:
                                if "ELB-HealthChecker/2.0" not in str(packet[HTTPRequest].User_Agent):
                                    #print(packet.show())
                                    row['client_ip'] = packet[HTTPRequest].X_Forwarded_For.decode('utf-8')
                                    #print( str(packet[HTTPRequest].X_Forwarded_For))
                                    row['target_ip'] = str(packet[IP].dst)
                                    row['request_method'] = packet[HTTPRequest].Method.decode('utf-8')
                                    row['request_url'] = packet[HTTPRequest].Host.decode('utf-8') + packet[HTTPRequest].Path.decode('utf-8')
                                    row['http_protocol'] = packet[HTTPRequest].Http_Version.decode('utf-8')
                                    row['user_agent'] = packet[HTTPRequest].User_Agent.decode('utf-8')
                                    requestProcessed = True
                            elif HTTPResponse in packet and requestProcessed == True:
                                #print(packet.show())
                                row['time'] = packet[HTTPResponse].Date.decode('utf-8')
                                #print(str(packet[HTTPResponse].Date))
                                row['http_response_code'] = packet[HTTPResponse].Status_Code.decode('utf-8')
                                row['username'] = ""
                                requestProcessed = False
                                print(row)
                    
                        '''
                        if packet.haslayer(TCP):
                            if packet[TCP].dport == 80:
                                if packet.haslayer(Raw):
                                    if "ELB-HealthChecker" not in str(packet[Raw].load):
                                        print(packet.show())                
                        '''
                    os.remove(filenames[i])

            else:
                sleep(0.2)


