# -*- coding: utf-8 -*-
"""
Laboratoire 1 partie 1
Nuno Miguel Cerca Abrantes Silva, Elie N'djoli

"""

from scapy.all import *
import sys

def packetHandler(packet):
    #Seul le Probe request sont analysé
    #Un Probe request correpond au type 0 et au sous-type 4
    if(packet.haslayer(Dot11ProbeReq)):
        #Si l'adresse MAC du probe request est égal à l'adresse que l'on
        # recherche on affiche son adresse mac avec son SSID 
        #Lors d'un Probe request l'adresse 2 correspond à l'adresse source
        if packet.addr2 == sys.argv[1].lower():            
            print("Client with MAC: %s detected" %(packet.addr2))

sniff(iface="wlan0mon", prn=packetHandler)


