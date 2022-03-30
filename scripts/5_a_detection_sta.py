#!/usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022

bssids = []

def PacketHandler(packet) :
    if packet.haslayer(Dot11ProbeReq):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        found_ssid = packet[Dot11Elt].info.decode()
        
        if found_ssid == ssid and bssid not in bssids:
            bssids.append(bssid)
            print("STA with mac", bssid, "try to connect to the SSID", ssid)


if __name__ == '__main__':
    import argparse
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script for creating a probe request evil twin attack with target SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'", default=DEFAULT_WLAN)
    parser.add_argument("-s", "--ssid", dest="ssid", help="the requested ssid", required=True)
    args = parser.parse_args()
    ssid = args.ssid
    iface = args.iface

    sniff(prn=PacketHandler, iface=iface)

