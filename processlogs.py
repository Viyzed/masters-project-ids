import mysql.connector as maria
import requests
from scapy.all import *
from scapy.layers.http import *
import os
from time import sleep
import datetime

class ProcessLogs:

    # glabal variable fro directory to store pcap files on localhost
    global directory
    directory = "pcaps"
    filenames = []

    # return a data-sorted array of files on the localhost
    def dirList():
        files = []
        for filename in os.scandir(directory):
            if filename.is_file():
                files.append(filename.path)
        return sorted(files)

    if __name__ == "__main__": 
        
        # feature names for outut response of packet capture
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
            
            # get downloaded files as name array
            filenames = dirList()

            # if there are more than 2 files stored 
            if len(filenames) > 2:

                # for each pcap file
                for i in range(len(filenames)):

                    # open mariadb connection for getting username information
                    db_connection = maria.connect(user='admin', password='Pa$$w0rd!', database='masters_maria_db_b', host='masters-maria-db-b.cohsjxuibh07.eu-west-1.rds.amazonaws.com', port='3306')
                    cursor = db_connection.cursor(buffered=True)
                    
                    # flag for processing HTTP Request packets, set to false so that Requests are processed before Responses
                    requestProcessed = False
                    
                    # set API response to empty response 
                    response = requests.Response()

                    # set readfile variable for pcap file in directory
                    cap = rdpcap(filenames[i])

                    # proccess each packet in capture
                    for packet in cap:
                        if HTTP in packet:

                            # process HTTP Request first
                            if HTTPRequest in packet:
                                if "ELB-HealthChecker/2.0" not in str(packet[HTTPRequest].User_Agent) and "aws-sdk-go" not in str(packet[HTTPRequest].User_Agent):

                                    # process client IP address
                                    if packet[HTTPRequest].X_Forwarded_For is not None: ip = packet[HTTPRequest].X_Forwarded_For.decode('utf-8')
                                    else: ip = str(packet[IP].src)
                                    
                                    # if client IP is not NULL get coutinent code and country code using geoplugin API
                                    if '.' in ip: 
                                        response = requests.get("http://www.geoplugin.net/json.gp?ip="+str(ip))
                                        if(response.json()['geoplugin_status'] == 200 or response.json()['geoplugin_status'] == 206):
                                            row['continent_code'] = response.json()['geoplugin_continentCode']
                                            row['country_code'] = response.json()['geoplugin_countryCode']
                                    else: 
                                        response = requests.Response()
                                        row['continent_code'] = ""
                                        row['country_code'] = ""
                                    
                                    row['client_ip'] = ip
                                    
                                    # process instance target IP
                                    if str(packet[IP].dst) is not None: row['target_ip'] = str(packet[IP].dst)

                                    # process http request method
                                    if packet[HTTPRequest].Method is not None: row['request_method'] = packet[HTTPRequest].Method.decode('utf-8')

                                    # process request url
                                    if packet[HTTPRequest].Host is not None: 
                                        url = packet[HTTPRequest].Host.decode('utf-8') + packet[HTTPRequest].Path.decode('utf-8')
                                        if ':80' in url:
                                            url = url.replace(':80', '')
                                        elif ':443' in url:
                                            url = url.replace(':443', '')
                                        row['request_url'] = url

                                    # process http protocol version
                                    if packet[HTTPRequest].Http_Version is not None: row['http_protocol'] = packet[HTTPRequest].Http_Version.decode('utf-8')
                                    
                                    # process user agent
                                    if packet[HTTPRequest].User_Agent is not None: row['user_agent'] = packet[HTTPRequest].User_Agent.decode('utf-8')

                                    # set HTTP Request processed to True
                                    requestProcessed = True

                            # if the HTTP Request has been processed, process the HTTP Response 
                            elif HTTPResponse in packet and requestProcessed == True:
                                
                                # process datatime to conform to correct format for database query
                                time_http = packet[HTTPResponse].Date.decode('utf-8')

                                time_split = time_http.split(' ')[3] + '-' + time_http.split(' ')[2] + '-' + time_http.split(' ')[1]  + ' ' + time_http.split(' ')[4]
                                time_split_seconds = int(time_split.split(':')[2])
                                if time_split_seconds > 0: time_split_seconds_before = str(time_split_seconds - 1)
                                else: time_split_seconds_before = str(time_split_seconds)
                                if time_split_seconds < 59: time_split_seconds_after = str(time_split_seconds + 1)
                                else: time_split_seconds_after = str(time_split_seconds)

                                # create datatimes for one second before datatime and one second after to ensure that 
                                # delay in http respoonse does not affect user activity recognition
                                time_split_before = time_split.split(':')[0] + ':' + time_split.split(':')[1] + ':' + time_split_seconds_before
                                time_split_after = time_split.split(':')[0] + ':' + time_split.split(':')[1] + ':' + time_split_seconds_after
                                time_object = datetime.datetime.strptime(time_split, "%Y-%b-%d %H:%M:%S") 
                                time_before_object = datetime.datetime.strptime(time_split_before, "%Y-%b-%d %H:%M:%S")
                                time_after_object = datetime.datetime.strptime(time_split_after, "%Y-%b-%d %H:%M:%S")
                                
                                time = str(time_object)
                                time_before = str(time_before_object)
                                time_after = str(time_after_object)
                                
                                row['time'] = time

                                # process response code
                                row['http_response_code'] = packet[HTTPResponse].Status_Code.decode('utf-8')
                                
                                # query mardiadb for user activity where datetime is within response bounds
                                query = "SELECT username FROM activity WHERE time = %s OR time = %s OR time = %s;"
                                cursor.execute(query, (time_before,time_after,time))
                                
                                if cursor.rowcount > 0:
                                    result = cursor.fetchall()
                                    result = result[0]
                                    username = result[0]
                                else: username = ""
                                
                                # add username if activity is discovered
                                row['username'] = username

                                # set Request Processed flag back to false
                                requestProcessed = False

                                # show curated output
                                print(row)
                                print(" ")
                    
                    # remove pcap file from localhost
                    os.remove(filenames[i])

            else:
                # if pcap directory is empty wait for one second
                sleep(1)


