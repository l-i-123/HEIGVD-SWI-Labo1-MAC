# -*- coding: utf-8 -*-
"""
Laboratoire 1 partie 2
Nuno Miguel Cerca Abrantes Silva, Elie N'djoli

"""

#from scapy.layers.l2 import *
from scapy.all import *
import urllib.request as urllib2
import sys
import json
import codecs

#ap_list = []
url = "http://macvendors.co/api/"
tab = {}

def packetHandler(packet):
    #Seul le Probe request sont analysé
    #Un Probe request correpond au type 0 et au sous-type 4
    if(packet.haslayer(Dot11ProbeReq)):
        #Recupération de l'adresse MAC source du paquet
        addr2 = packet.addr2
        #envoie d'une requete à l'API du site http://macvendors.co/api/ afin
        # qu'il nous renvoie le fabriquant de l'appareil source
        request = urllib2.Request(url+addr2, headers={'User-Agent' : "API Browser"})
        # Reception de la réponse de http://macvendors.co/api/
        response = urllib2.urlopen(request)
        #Définition de l'encodage
        reader = codecs.getreader("utf-8")
        
        #création de l'objet JSON contenant les information du fabriquant
        if((response is not None) and (request is not None)):
            obj = json.load(reader(response))
        
        
        if(obj['result'].get('company') is not None):
            # si l'adresse MAC source n'est pas encore dans le tableau tab
            # il est ajouté et affiche aussi le nom du fabriquant de l'appareil
            if((addr2 in tab) == False):
                tab[str(addr2)] = str(addr2) + str(" (") + str(obj['result'].get('company')) + str(") -")
    
            chaine = ""
            #Suppression du premier caractère de la chaine si elle commence par b
            #La chaine contient le SSID du réseau recherché
            if(packet.info is not None):
                chaine = chaine + str(packet.info)
            if chaine.startswith("b"):
                 chaine = chaine[len("b"):]
            #Si la chaine n'est pas vide on vérifie que le SSID qu'elle 
            # contient ne figure pas déjà dans la liste de ses SSID
            if (len(chaine) > 2):
                if(chaine not in tab[str(addr2)]):
                    #Si la chaine contient déjà un SSID une virgule est ajouté
                    # à la suite de la chaine correspondant à ladresse MAC
                    if("'" in tab[str(addr2)]):
                        tab[str(addr2)] = tab[str(addr2)] + ", " + chaine
                    #Si il c'est le première SSID de la liste 
                    else:
                        tab[str(addr2)] = tab[str(addr2)] + chaine
                    print(str(tab[addr2]))

sniff(iface="wlan0mon", prn=packetHandler)
                                

#print(ap_list)
