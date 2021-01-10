from scapy.all import *
import sys
import os

def captureHandshake():
	for packet in cap:
		if packet.type == handshake:
			return packet.info


def casserMDP(MDPchiffre):
	filin = open("rockyou.txt", "r")
	lignes = filin.readlines()
	for mdpTest in lignes:
		if chiffrement(mdpTest) == MDPchiffre:
			return mdpTest
