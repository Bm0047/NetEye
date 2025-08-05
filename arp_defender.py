import scapy.all as scapy
import time
import threading
from colorama import Fore, Style, init
import os
import sys
import logging

init(autoreset=True)

# A dictionary to store the trusted IP-to-MAC mappings
TRUSTED_MACS = {}
# A flag to stop the sniffer thread gracefully
stop_defender_event = threading.Event()
# A flag to check if the active countermeasure is running
countermeasure_active = threading.Event()
# A timestamp for the last detected attack, used for automatic countermeasure shutdown
last_attack_time = 0
# A simple dictionary for MAC vendor lookup
MAC_VENDORS = {
    "00:15:5d": "Microsoft",
    "00:0c:29": "VMware",
    "f4:98:86": "Apple",
    "7c:f5:12": "Cisco",
    "50:c7:bf": "TP-Link",
    "a8:1c:69": "Intel",
}

# --- Logging Configuration ---
log_file = "arp_defender.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress Scapy warnings

def get_mac(ip):
    """
    Retrieves the MAC address for a given IP address.
    """
    try:
        # Send an ARP request to the IP and get the response
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        for _, rcv in ans:
            return rcv.hwsrc
    except Exception as e:
        print(f"{Fore.RED}Error getting MAC for {ip}: {e}{Style.RESET_ALL}")
    return None

def get_mac_vendor(mac_address):
    """
    Performs a simple lookup to get the vendor of a MAC address.
    A more robust solution would use a full MAC OUI database.
    """
    oui = mac_address[:8].lower()
    return MAC_VENDORS.get(oui, "Unknown Vendor")

def find_gateway_ip():
    """Finds the IP address of the default gateway (router)."""
    try:
        # Use scapy's route table to find the gateway
        return scapy.conf.route.route('0.0.0.0')[2]
    except Exception as e:
        print(f"{Fore.RED}Error finding gateway IP: {e}{Style.RESET_ALL}")
        return None

def get_all_ips_on_network(gateway_ip):
    """
    Scans the network to find all active IPs.
    """
    print(f"\n{Fore.CYAN}Scanning network for active devices to protect...{Style.RESET_ALL}")
    ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=f"{gateway_ip}/24"), timeout=3, verbose=False)
    active_ips = [rcv.psrc for _, rcv in ans]
    return active_ips

def populate_trusted_macs(gateway_ip_input):
    """
    Populates the TRUSTED_MACS dictionary with the gateway's MAC address.
    """
    if gateway_ip_input:
        gateway_ip = gateway_ip_input
    else:
        gateway_ip = find_gateway_ip()

    if not gateway_ip:
        print(f"{Fore.RED}Could not determine gateway IP. Please provide it manually.{Style.RESET_ALL}")
        return False, None

    print(f"{Fore.YELLOW}Looking for the router's IP and MAC address...{Style.RESET_ALL}")
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac:
        TRUSTED_MACS[gateway_ip] = gateway_mac
        print(f"{Fore.GREEN}Trusted Gateway IP: {gateway_ip} -> MAC: {gateway_mac}{Style.RESET_ALL}")
        return True, gateway_ip
    else:
        print(f"{Fore.RED}Could not find gateway MAC address. Exiting.{Style.RESET_ALL}")
        return False, None

def restore_arp_proactively(gateway_ip, gateway_mac, target_ips):
    """
    Continuously sends correct ARP responses to restore the network's ARP tables.
    This function will run in a separate thread.
    """
    restore_counter = 0
    inactivity_timeout = 60 # seconds
    
    global last_attack_time
    last_attack_time = time.time() # Start the timer when the countermeasure begins

    while countermeasure_active.is_set():
        # Check if the attack has stopped for the inactivity timeout period
        if time.time() - last_attack_time > inactivity_timeout:
            print(f"\n{Fore.GREEN}[-] No malicious packets detected for {inactivity_timeout} seconds. The network appears secure.{Style.RESET_ALL}")
            choice = input(f"{Fore.YELLOW}Do you want to terminate the countermeasure? (y/n): {Style.RESET_ALL}").lower()
            if choice == 'y':
                print(f"\n{Fore.GREEN}Countermeasure terminated by user. Defender is now in passive monitoring mode.{Style.RESET_ALL}")
                
                # --- MODIFIED CODE BLOCK ---
                print(f"\n{Fore.YELLOW}Returning to main menu in 5 seconds...{Style.RESET_ALL}")
                time.sleep(5)
                # --- END OF MODIFIED BLOCK ---
                
                countermeasure_active.clear()
                return
            else:
                print(f"\n{Fore.YELLOW}Continuing active defense. The script will re-prompt if no attacks are detected for another {inactivity_timeout} seconds.{Style.RESET_ALL}")
                last_attack_time = time.time() # Reset the timer to re-prompt later
            
        for ip in target_ips:
            # Craft a correct ARP response for the gateway and send it to all IPs
            packet = scapy.ARP(op=2, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac)
            scapy.send(packet, verbose=False)
        
        time.sleep(2) # Send every 2 seconds to combat spoofing
        restore_counter += 1
        if restore_counter % 5 == 0 and countermeasure_active.is_set():  # Print status every 10 seconds (5 * 2s)
            print(f"{Fore.GREEN}[+] Countermeasure is active and defending the network...{Style.RESET_ALL}")

def check_arp_packet(packet):
    """
    The core defensive function for ARP. Checks for suspicious ARP packets
    and logs forensic details if a spoof is detected.
    """
    global last_attack_time

    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # op=2 is an ARP response
        sender_ip = packet[scapy.ARP].psrc
        sender_mac = packet[scapy.ARP].hwsrc
        
        # Check if the sender's IP is in our trusted list (e.g., the gateway)
        if sender_ip in TRUSTED_MACS:
            # Check if the MAC address in the packet matches the trusted MAC
            if sender_mac != TRUSTED_MACS[sender_ip]:
                last_attack_time = time.time() # Update the last attack time
                
                if countermeasure_active.is_set():
                    # If the countermeasure is active, just log the neutralization
                    print(f"{Fore.YELLOW}[-] Malicious packet detected from {sender_mac} but was neutralized.{Style.RESET_ALL}")
                    logging.info(f"Malicious packet neutralized! Attacker MAC: {sender_mac}, Spoofed IP: {sender_ip}")
                    return
                
                # An attack is detected! Log and print forensic details.
                vendor = get_mac_vendor(sender_mac)
                
                # Print the warning to the console
                print(f"\n{Fore.RED}{Style.BRIGHT}[!!!] ARP Spoofing Attack Detected!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}------------------- ATTACK DETAILS -------------------{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  - Attacker's MAC Address: {Style.BRIGHT}{sender_mac}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  - Estimated Vendor: {Style.BRIGHT}{vendor}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  - Spoofed IP Address: {Style.BRIGHT}{sender_ip}{Style.RESET_ALL}")
                print(f"{Fore.RED}  - This does not match the trusted MAC {TRUSTED_MACS[sender_ip]}.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}------------------------------------------------------{Style.RESET_ALL}")

                # Log the details to the file
                logging.info(f"ARP Spoofing Attack Detected! Attacker MAC: {sender_mac}, "
                             f"Estimated Vendor: {vendor}, Spoofed IP: {sender_ip}")

                # Ask the user if they want to launch the countermeasure
                choice = input(f"\n{Fore.YELLOW}Do you want to launch a countermeasure to stop this attack? (y/n): {Style.RESET_ALL}").lower()
                if choice == 'y':
                    countermeasure_active.set()
                    # Get the gateway IP and MAC from the trusted list
                    gateway_ip = list(TRUSTED_MACS.keys())[0]
                    gateway_mac = TRUSTED_MACS[gateway_ip]
                    
                    # Find all other IPs on the network to send restoration packets to
                    all_ips = get_all_ips_on_network(gateway_ip)
                    
                    # Start a new thread for the countermeasure
                    countermeasure_thread = threading.Thread(
                        target=restore_arp_proactively, 
                        args=(gateway_ip, gateway_mac, all_ips)
                    )
                    countermeasure_thread.daemon = True
                    countermeasure_thread.start()
                    print(f"\n{Fore.GREEN}{Style.BRIGHT}Countermeasure launched! The attack is now being actively neutralized. The console will show neutralization updates.{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.YELLOW}Countermeasure not launched. Defender will continue to log detections.{Style.RESET_ALL}")

def start_arp_defender():
    """
    Initializes and starts the ARP spoofing detection and active defense tool.
    """
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Starting ARP Spoofing Defender{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return

    gateway_ip_input = input(f"{Fore.YELLOW}Enter Gateway IP (press Enter to auto-detect): {Style.RESET_ALL}")

    success, gateway_ip = populate_trusted_macs(gateway_ip_input)
    if not success:
        return

    print(f"\n{Fore.GREEN}Defender is now active and monitoring for ARP spoofing. Press Ctrl+C to stop.{Style.RESET_ALL}")

    try:
        scapy.sniff(
            filter="arp",
            prn=check_arp_packet,
            store=0
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}Shutting down ARP Defender...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred during sniffing: {e}{Style.RESET_ALL}")
    finally:
        stop_defender_event.set()
        countermeasure_active.clear()
        print(f"{Fore.CYAN}ARP Defender stopped.{Style.RESET_ALL}")

# Entry point for the module when it's run directly
if __name__ == "__main__":
    start_arp_defender()