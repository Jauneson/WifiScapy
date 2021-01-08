#!/usr/bin/python

from scapy.all import *
import sys
import signal
import os

def actionPacket(packets):
   for packet in packets:
       print(packet.show())
       print(packet.show2())
       #print(packet[Dot11Elt].info)

if __name__ == "__main__":
    os.system('ifconfig wlan0 down')
    os.system('iwconfig wlan0 mode monitor')
    os.system('ifconfig wlan0 up')
    global ssid_list
    ssid_list ={}
    global s
    s = conf.L2socket(iface="wlan0")
    sniff(prn=actionPacket, iface="wlan0", store=0)

