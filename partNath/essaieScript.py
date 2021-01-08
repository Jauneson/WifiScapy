#!/usr/bin/python

from scapy.all import *
import sys
import signal
import os

def actionPacket(packets):
    print(packet[0])
    #for packet in packets:
       # print(packet.show())


if __name__ == "__main__":
    os.system('ifconfig wlan0 down')
    os.system('iwconfig wlan0 mode monitor')
    os.system('ifconfig wlan0 up')
    sniff(prn=actionPacket, iface="wlan0")

