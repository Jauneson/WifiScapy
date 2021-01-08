from scapy.all import *
import sys
import os



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
os.system('ifconfig ' + interface + ' down') #on passe l'interface en down
try:
	os.system('iwconfig ' + interface + ' mode monitor')
except:														#si ça ne marche pas, erreur
	print("l'interface n'existe pas ou n'est pas détectée")
	exit(1)
os.system('ifconfig ' + interface + ' up')
print("\n l'interface est désormais en mode monitor")
