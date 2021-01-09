from scapy.all import *
import sys
import os


#on vérifie que le paquet soit un beacon frame pour l'afficher

def action_packets(packet):
	#print(packet.show())
	if packet.haslayer(Dot11):
		if packet.type == 0 and packet.subtype == 8:
			print("Point d'accès: %s , SSID: %s \n" %(packet.addr2, packet.info))


#main

print("Vous devez avoir les privilèges root pour executer ce script.")
answer=input(" Continuer? (O/n)")
if answer != "o" and answer != "O":
	print("stop")
	exit(1)
print("Continue \n")
interface=input("Veuillez entrer le nom de votre interface wifi (iwconfig pour la connaitre)")
print("passage de l'interface en mode monitor: \n")
print("(executer le script restart_network.sh pour repasser en mode managed)")
os.system("killall wpa_supplicant")
os.system("killall NetworkManager")
os.system('ifconfig ' + interface + ' down') #on passe l'interface en down
try:
	os.system('iwconfig ' + interface + ' mode monitor')
except:														#si ça ne marche pas, erreur
	print("l'interface n'existe pas ou n'est pas détectée")
	exit(1)
os.system('ifconfig ' + interface + ' up')
print("\nl'interface est désormais en mode monitor\nLancement sniffer...")
sniff(iface=interface, prn=action_packets)
