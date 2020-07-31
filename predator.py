#!/bin/python3
from riposte import Riposte
import os
import sys
from colorama import Fore, Back, Style 
import multiprocessing
import time
import terminal_banner
from pyhunter import PyHunter
import pandas as pd
import whois
from shodan import Shodan
import socket
import requests
from email_hunter import EmailHunterClient
import json
from scapy.all import ARP, Ether, srp
from scapy.all import *
from threading import Thread
import pandas
import time
import sys
import subprocess 
from texttable import Texttable
import nmap

def banner():

	os.system("clear")
	print(Fore.YELLOW + "                                    /$$             /$$                         ")
	print(Fore.YELLOW + "                                    | $$            | $$                        ")
	print(Fore.YELLOW + "  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$ ")
	print(Fore.YELLOW + " /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ |____  $$|_  $$_/   /$$__  $$ /$$__  $$")
	print(Fore.YELLOW + "| $$  \ $$| $$  \__/| $$$$$$$$| $$  | $$  /$$$$$$$  | $$    | $$  \ $$| $$  \__/")
	print(Fore.YELLOW + "| $$  | $$| $$      | $$_____/| $$  | $$ /$$__  $$  | $$ /$$| $$  | $$| $$      ")
	print(Fore.YELLOW + "| $$$$$$$/| $$      |  $$$$$$$|  $$$$$$$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$      ")
	print(Fore.YELLOW + "| $$____/ |__/       \_______/ \_______/ \_______/   \___/   \______/ |__/      ")
	print(Fore.YELLOW + "| $$                                                                            ")
	print(Fore.YELLOW + "| $$                                                                            ")
	print(Fore.YELLOW + "|__/                                                                            ")

    	                                                              
	
	print("""
    ***  This is a tool to automate task for pentesters with the cyberkill chain in mind.
        *** Author: Alpha__kong 
        *** follow youtube@shadow sec
        *** This tool is developed for educatinal purposes only. 
        *** twitter @ shadow sec
        *** THE BEST DEFENCE IS ATTACKING
        *** Version 1.0.0""")


banner()
repl = Riposte(prompt=("Shell >>>>"))

#@repl.command("shodan")
#def shodan():
#	api = Shodan('PTOGtwIBbzo94uBaaFVs7PEOQmZGJ0w2')
#	x = str(input("Enter the IP address: "))
#	ipinfo = api.host(str(x))
#	repl.print(ipinfo)
#	for port in ipinfo:
#		repl.print(ports)
#		print("DONE")
	

@repl.command("domain_scanner")
def domain_scanner():
	data = str(input("Enter the domain to scan: "))
	hunter = PyHunter('f426ae0e0b3b14b8854e48bc3ba268522f3674fa')
	l = hunter.domain_search(data)
	print(l)

#@repl.command("netinfo")
#def netinfo():
#	a = os.system("hostname -I")
	#b = os.system("curl ifconfig.me")
 #	print(a)

@repl.command("active_devices")
def active_devices():
	data1 = os.system('curl	ifconfig.me')
	data2 = os.system('hostname -I')
	print("External IP ", data1)
	print("Internal IP ", data2)
	#print("External IP is = " ,data1)
	target_ip = "192.168.0.0/24"
	arp = ARP(pdst="192.168.0.0/24")
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether/arp
	result = srp(packet, timeout=3,verbose=0) [0]
	clients = []
	for sent, received in result:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc})
	print("Available device in the network: ")
	t = Texttable()
	t.add_rows([['IP address', 'MAC'], [data1, 10], [data2, 11]])
	print(t.draw())
	print(Fore.GREEN + "ip" + " "*18+"MAC")
	for client in clients:
		print("{:16}    {}".format(client['ip'], client['mac']))

@repl.command("1")
def information_gathering():
	print("1.Shodan Scan")
@repl.command("nmap-scanner")
def nmap_scanner():
	y = str(input("Enter the IP address or domain: "))
	print("1.Basic scan")
	print("2.Vulnerability scan")
	print("3.Specific scan")
	opn_nmap = int(input("Select your option: "))
	if opn_nmap == 1:
		B_scan = subprocess.call(["nmap", "-sC","-sV","-A",y])
		print(B_scan)
	if opn_nmap ==  2:
		V_scan = subprocess.call(["nmap", "-Pn", "--script", "vuln", V_opn])
		print(V_scan)
	if opn_nmap == 3:
		print("done")


@repl.command("scanner")
def scanner():
	domain_name = str(input("Enter the domain name: "))
	domain_IP = (socket.gethostbyname(domain_name))
	print(domain_IP)
	print(Fore.GREEN + "1.Shodan Scan")
	scanner_options = int(input("Enter your option: "))
	print("done")
@repl.command("smb")
def SMB():
	print(Fore.BLUE + "1.Users")
	print(Fore.BLUE + "2.External_Blue")
	print(Fore.BLUE + "2.SMB_ghost")
	print(Fore.BLUE + "3.LMNR_POISONING")

	def Users():
		print("Development")
	def External_Blue():
		print("External_Blue")
	#test123()
	def SMB_ghost():
		print("SMB_ghost")
	def LMNR_POISONING():
		print("LMNR_POISONING")
	#test1234()
	opn = int(input("Select Your options: "))
	if opn == 1:
		External_Blue()
	if opn == 2:
		SMB_ghost()
	if opn == 3:
		LMNR_POISONING()


@repl.command("exit")
def exit():
	sys.exit()
@repl.command("Network_Info")
def Network_Info():
	syscom = os.system("nmcli -p")
	print(syscom)
@repl.command("options")
def options():
	repl.success("[1].Wireless Attacks")
	repl.success("[2].RECONNAISSANCE")
	repl.success("[3].WEAPONISATION")
	repl.success("[4].DELIVERY")
	repl.success("[5].EXPLOITATION")
	repl.success("[6].COMMAND && CONTROL")
repl.run()
