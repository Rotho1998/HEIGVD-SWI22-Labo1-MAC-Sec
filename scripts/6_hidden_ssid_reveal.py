#!/usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022
# Source : https://www.youtube.com/watch?v=_OpmfE43AiQ&ab_channel=PentesterAcademyTV

from scapy.all import *
import socket

hidden_ssid_aps = set()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
        # We check if the attribute info is empty, wich is the case when the ssid is hidden
        if not pkt.info:
            # Check if the network is already in the list
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print("Hiddden ssid network found:", pkt.addr3)
    # Search of the name of the hidden network already founded, when an STA connect to the AP
    elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_ssid_aps):
        print("Hidden ssid uncovered: " + pkt.addr3 + " -> " + pkt.info.decode())

if __name__ == '__main__':
    import argparse
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script for getting the hidden SSIDs")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'", default=DEFAULT_WLAN)
    args = parser.parse_args()
    iface = args.iface
    
    print("Searching for hidden SSIDs")
    sniff(prn=PacketHandler, iface=iface)

