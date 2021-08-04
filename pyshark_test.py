import pyshark
import collections
import matplotlib.pyplot as plt
import numpy as np

capture = pyshark.LiveCapture(interface='ens3', only_summaries=False, display_filter='http')
capture.sniff(timeout=50)
capture
protocolList = []

for packet in capture.sniff_continuously(packet_count=5):
    #line = str(packet)
    #formattedLine = line.split(" ")
    #protocolList.append(formattedLine[4])
    #print(formattedLine[4])
    print("New packet", packet)
    
