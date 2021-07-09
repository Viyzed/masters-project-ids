import logging
import pyshark

p = pyshark.FileCapture("/tmp/capture.pcap")

#for pkt in p:

pkt = p[0]
print(pkt.layers)
print("IP" in pkt)
print(pkt.http.pretty_print)
