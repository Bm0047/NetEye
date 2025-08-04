import scapy.all as scapy
import threading
from colorama import Fore, Style, init
import os

init(autoreset=True)

TRUSTED_DNS_SERVERS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9"
}

stop_defender_event = threading.Event()

def get_current_dns_servers():
    """
    Attempts to get the DNS servers configured on the system.
    """
    try:
        if os.name == 'nt':
            print(f"{Fore.YELLOW}Automatic DNS server detection on Windows is complex. Please manually add your router IP to the trusted list.{Style.RESET_ALL}")
            return []
        else:
            with open('/etc/resolv.conf', 'r') as f:
                lines = f.readlines()
                return [line.split()[1] for line in lines if line.strip().startswith('nameserver')]
    except Exception as e:
        print(f"{Fore.RED}Error detecting DNS servers: {e}{Style.RESET_ALL}")
        return []

def check_dns_packet(packet):
    """
    The core defensive function for DNS. Checks for suspicious responses.
    """
    if stop_defender_event.is_set():
        return

    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSRR):
        if packet[scapy.IP].src not in TRUSTED_DNS_SERVERS:
            if packet[scapy.DNS].qd and packet[scapy.DNSRR].rrname:
                print(f"\n{Fore.RED}{Style.BRIGHT}[DNS SPOOFING ALERT]{Style.RESET_ALL}")
                print(f"{Fore.RED}  Suspicious DNS response for '{packet[scapy.DNS].qd.qname.decode()}'")
                print(f"  Received from untrusted IP: {Style.BRIGHT}{packet[scapy.IP].src}{Style.RESET_ALL}")
                print(f"  This does not match our trusted DNS servers.")
                print(f"  A DNS spoofing attack may be in progress!{Style.RESET_ALL}")

def start_dns_defender():
    """
    Initializes and starts the DNS spoofing detection tool.
    """
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Starting DNS Spoofing Defender{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return

    for server in get_current_dns_servers():
        TRUSTED_DNS_SERVERS.add(server)

    print(f"{Fore.GREEN}Trusted DNS Servers: {', '.join(TRUSTED_DNS_SERVERS)}{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Defender is now active and monitoring for DNS spoofing. Press Ctrl+C to stop.{Style.RESET_ALL}")
    
    try:
        scapy.sniff(
            filter="udp port 53",
            prn=check_dns_packet,
            store=0,
            stop_event=stop_defender_event
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}DNS Defender stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred during sniffing: {e}{Style.RESET_ALL}")
    finally:
        stop_defender_event.set()

if __name__ == "__main__":
    start_dns_defender()