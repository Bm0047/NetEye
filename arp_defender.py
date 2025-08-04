import scapy.all as scapy
import time
import threading
from colorama import Fore, Style, init
import os
import sys

init(autoreset=True)

# A dictionary to store the trusted IP-to-MAC mappings
TRUSTED_MACS = {}

# A flag to stop the sniffer thread gracefully
stop_defender_event = threading.Event()

def get_mac(ip):
    """
    Retrieves the MAC address for a given IP address.
    """
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        for _, rcv in ans:
            return rcv.hwsrc
    except Exception as e:
        print(f"{Fore.RED}Error getting MAC for {ip}: {e}{Style.RESET_ALL}")
    return None

def find_gateway_ip():
    """Finds the IP address of the default gateway (router)."""
    try:
        import netifaces
        gws = netifaces.gateways()
        gateway_ip = gws['default'][netifaces.AF_INET][0]
        return gateway_ip
    except ImportError:
        print(f"{Fore.YELLOW}netifaces module not found. Please install it (`pip install netifaces`).{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Using a fallback method to find the gateway.{Style.RESET_ALL}")
        try:
            import psutil
            for route in psutil.net_if_addrs().values():
                for addr in route:
                    if addr.family == scapy.AF_INET:
                        return scapy.conf.route.route('0.0.0.0')[2]
        except (ImportError, IndexError):
            print(f"{Fore.RED}Fallback failed. Cannot automatically find gateway.{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}Could not determine the gateway IP: {e}{Style.RESET_ALL}")
    return None

def populate_trusted_macs(gateway_ip, interface):
    """
    Populates the TRUSTED_MACS dictionary with the correct MAC address for the gateway.
    """
    print(f"{Fore.GREEN}Looking for the router's IP and MAC address...{Style.RESET_ALL}")
    
    if not gateway_ip:
        gateway_ip = find_gateway_ip()
    
    if not gateway_ip:
        print(f"{Fore.RED}Cannot proceed without the gateway IP. Please restart and provide it manually.{Style.RESET_ALL}")
        return False
        
    gateway_mac = get_mac(gateway_ip)
    
    if gateway_mac:
        TRUSTED_MACS[gateway_ip] = gateway_mac
        print(f"{Fore.GREEN}Trusted Gateway IP: {Style.BRIGHT}{gateway_ip}{Style.RESET_ALL} -> MAC: {Style.BRIGHT}{gateway_mac}{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}Failed to get MAC address for the gateway. Check network connectivity.{Style.RESET_ALL}")
        return False

def check_arp_packet(packet):
    """
    The core defensive function. Checks for suspicious ARP packets.
    """
    if stop_defender_event.is_set():
        return
        
    if packet.haslayer(scapy.ARP):
        sender_ip = packet[scapy.ARP].psrc
        sender_mac = packet[scapy.ARP].hwsrc

        if sender_ip in TRUSTED_MACS:
            if sender_mac != TRUSTED_MACS[sender_ip]:
                print(f"\n{Fore.RED}{Style.BRIGHT}[ARP SPOOFING ALERT]{Style.RESET_ALL} IP {sender_ip} claims to be at MAC {sender_mac}.")
                print(f"{Fore.RED}{Style.BRIGHT}  This does not match the trusted MAC {TRUSTED_MACS[sender_ip]}.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  A spoofing attack may be in progress!{Style.RESET_ALL}")

def start_arp_defender():
    """
    Initializes and starts the ARP spoofing detection tool.
    """
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Starting ARP Spoofing Defender{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return

    gateway_ip_input = input(f"{Fore.YELLOW}Enter Gateway IP (press Enter to auto-detect): {Style.RESET_ALL}")

    if not populate_trusted_macs(gateway_ip_input or None, scapy.conf.iface):
        return

    print(f"\n{Fore.GREEN}Defender is now active and monitoring for ARP spoofing. Press Ctrl+C to stop.{Style.RESET_ALL}")

    try:
        scapy.sniff(
            filter="arp",
            prn=check_arp_packet,
            store=0,
            stop_event=stop_defender_event
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}ARP Defender stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred during sniffing: {e}{Style.RESET_ALL}")
    finally:
        stop_defender_event.set()

if __name__ == "__main__":
    start_arp_defender()