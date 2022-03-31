#!/usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022
# source : https://stackoverflow.com/questions/52981542/python-scapy-distinguish-between-acesspoint-to-station

from scapy.all import *

# Allow to use a dictionnary in Python
connections = {}

def PacketHandler(packet) :
    if packet.haslayer(Dot11) and packet.type == 2: #Data frame
        DS = packet.FCfield & 0x3
        # Allow us to check who sent
        toDS = DS & 0x01 != 0
        fromDS = DS & 0x2 != 0
        # From the STA to the AP
        if toDS and not fromDS:
            connections[packet.addr2] = packet.addr1
        # From the AP to the STA
        if not toDS and fromDS:
            connections[packet.addr1] = packet.addr2


if __name__ == '__main__':
    import argparse
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script to check which sta is connected to an ap")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'", default=DEFAULT_WLAN)
    args = parser.parse_args()
    iface = args.iface

    # Set timeout to a higher value if you want more result
    sniff(prn=PacketHandler, iface=iface, timeout=30)

    # Print the result
    print("STAs                      APs")
    for k, v in connections.items():
        print(k + '    ' + v)

