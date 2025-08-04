import os
import sys
import time
import threading
import logging
import smtplib
from email.message import EmailMessage
from collections import defaultdict, deque
import requests
from colorama import Fore, Style, init
from art import text2art
import psutil
import configparser
import getpass
import socket
import nmap
from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw

# Import the new modular scripts
import arp_spoof
import mitm_spoof
import dns_spoof
import arp_defender
import dns_defender

# Initialize colorama for cross-platform color support
init(autoreset=True)

# --- Function to automatically find the active network interface ---
def find_active_interface():
    """Finds the name of the active network interface with an IPv4 address."""
    try:
        addrs = psutil.net_if_addrs()
        for interface_name, interface_addrs in addrs.items():
            for addr in interface_addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    print(f"{Fore.GREEN}Automatically detected interface: {Style.BRIGHT}{interface_name}{Style.NORMAL} with IP: {addr.address}{Style.RESET_ALL}")
                    return interface_name
        
        print(f"{Fore.RED}Error: Could not automatically detect an active network interface.{Style.RESET_ALL}")
        print(f"Please ensure you are connected to a network and run the script again.")
        return None
    except Exception as e:
        print(f"{Fore.RED}An error occurred during interface detection: {e}{Style.RESET_ALL}")
        return None

# --- Load Configuration from file ---
config = configparser.ConfigParser()
CONFIG_FILE = 'config.ini'

if not os.path.exists(CONFIG_FILE):
    print(f"{Fore.RED}Error: Configuration file '{CONFIG_FILE}' not found!{Style.RESET_ALL}")
    print(f"Please create a '{CONFIG_FILE}' file with the required settings.")
    exit()

config.read(CONFIG_FILE)

# --- Global Configuration and State Variables ---
LOCAL_IP = config['Network']['local_ip']
EMAIL_ALERTS = config.getboolean('Email', 'email_alerts')
REPORTING_INTERVAL = config.getint('Email', 'reporting_interval') * 60
EMAIL_SERVER = config['Email']['email_server']
EMAIL_PORT = config['Email']['email_port']
DDoS_THRESHOLD = config.getint('Detection', 'ddos_threshold')
DDoS_TIME_WINDOW = config.getint('Detection', 'ddos_time_window')
PORT_SCAN_THRESHOLD = config.getint('Detection', 'port_scan_threshold')
PORT_SCAN_TIME_WINDOW = config.getint('Detection', 'port_scan_time_window')
SESSION_TIMEOUT = config.getint('Detection', 'session_timeout')
malicious_strings_str = config['Detection']['malicious_strings']
MALICIOUS_STRINGS = [s.strip().encode('utf-8') for s in malicious_strings_str.split(',')]

logging.basicConfig(
    filename='neteye.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ddos_tracker = defaultdict(lambda: {"count": 0, "last_seen": time.time()})
port_scan_tracker = defaultdict(lambda: {"ports": set(), "last_seen": time.time()})
active_sessions = {}
IP_CACHE = {}
report_queue = deque()
EMAIL_USERNAME = None
EMAIL_PASSWORD = None
is_sniffing_active = False
is_periodic_reporting_active = False
active_interface = None


# --- Functions ---
def ensure_email_credentials():
    """Prompts for email credentials if they are not already set."""
    global EMAIL_USERNAME, EMAIL_PASSWORD

    if not EMAIL_ALERTS:
        print(f"{Fore.RED}Email alerts are not enabled in config.ini. Cannot perform this action.{Style.RESET_ALL}")
        return False
        
    if EMAIL_USERNAME and EMAIL_PASSWORD:
        return True
    
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Email Credentials Required:{Style.RESET_ALL}")
    print(f"Note: This tool uses an App Password, not your regular email password.")
    print(f"Please enter your email credentials to proceed.\n")
    EMAIL_USERNAME = input(f"{Fore.YELLOW}Email Address:{Style.RESET_ALL} ")
    EMAIL_PASSWORD = getpass.getpass(prompt=f"{Fore.YELLOW}App Password (hidden):{Style.RESET_ALL} ")
    
    return True

def get_os_from_ttl(ttl):
    """Guesses the OS based on the Time-To-Live (TTL) value."""
    if ttl > 128:
        return "Linux/Unix"
    if 100 < ttl <= 128:
        return "Windows"
    if 0 < ttl <= 64:
        return "Linux/Unix"
    return "Unknown"

def get_ip_info(ip):
    """Fetches and caches geolocation information for an IP address."""
    if ip in IP_CACHE and time.time() - IP_CACHE[ip]['timestamp'] < 3600:
        return IP_CACHE[ip]['info']
    
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=2)
        response.raise_for_status()
        info = response.json()
        if info['status'] == 'success':
            IP_CACHE[ip] = {'info': info, 'timestamp': time.time()}
            return info
        return None
    except Exception as e:
        logging.error(f"Failed to get IP info for {ip}: {e}")
        return None

def send_alert(alert_message, alert_type, ip_address=None, os_guess=None):
    """Prints, logs, and optionally emails a formatted and categorized alert."""
    
    alert_prefixes = {
        "suspicious_inbound": f"{Fore.RED}[SUSPICIOUS INBOUND]{Style.RESET_ALL}",
        "port_scan": f"{Fore.MAGENTA}[PORT SCAN]{Style.RESET_ALL}",
        "ddos_attack": f"{Fore.YELLOW}[DDoS ATTACK]{Style.RESET_ALL}",
        "malicious_payload": f"{Fore.LIGHTRED_EX}[MALICIOUS PAYLOAD]{Style.RESET_ALL}"
    }

    prefix = alert_prefixes.get(alert_type, f"{Fore.WHITE}[ALERT]{Style.RESET_ALL}")
    
    full_message = f"{prefix:25} {alert_message}"
    
    if os_guess:
        full_message += f" | {Fore.GREEN}OS:{Style.RESET_ALL} {os_guess}"

    if ip_address:
        ip_info = get_ip_info(ip_address)
        if ip_info and ip_info['status'] == 'success':
            full_message += f" | {Fore.CYAN}Geo:{Style.RESET_ALL} {ip_info['country']}, {ip_info['city']}"
            full_message += f" | {Fore.CYAN}ISP:{Style.RESET_ALL} {ip_info['isp']}"
    
    logging.warning(full_message)
    print(full_message)
    
    report_queue.append(full_message)

def analyze_packet(packet):
    """Analyzes a single captured packet with advanced logic."""
    global ddos_tracker, port_scan_tracker, active_sessions

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    ttl_value = packet[IP].ttl
    os_guess = get_os_from_ttl(ttl_value)

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        sport = layer.sport
        dport = layer.dport

        if dst_ip == LOCAL_IP:
            session_key = (src_ip, sport, dst_ip, dport)
            if session_key not in active_sessions:
                send_alert(f"New connection on port {dport} from {src_ip}", "suspicious_inbound", src_ip, os_guess)
            else:
                active_sessions[session_key] = time.time()
        elif src_ip == LOCAL_IP:
            session_key = (src_ip, sport, dst_ip, dport)
            active_sessions[session_key] = time.time()

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        if time.time() - ddos_tracker[src_ip]["last_seen"] > DDoS_TIME_WINDOW:
            ddos_tracker[src_ip]["count"] = 0
            ddos_tracker[src_ip]["last_seen"] = time.time()
        ddos_tracker[src_ip]["count"] += 1
        if ddos_tracker[src_ip]["count"] > DDoS_THRESHOLD:
            send_alert(f"Attack from {src_ip}! {ddos_tracker[src_ip]['count']} SYN packets in last {DDoS_TIME_WINDOW}s.", "ddos_attack", src_ip, os_guess)
            del ddos_tracker[src_ip]

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        if time.time() - port_scan_tracker[src_ip]["last_seen"] > PORT_SCAN_TIME_WINDOW:
            port_scan_tracker[src_ip] = {"ports": set(), "last_seen": time.time()}
        port_scan_tracker[src_ip]["ports"].add(packet[TCP].dport)
        port_scan_tracker[src_ip]["last_seen"] = time.time()
        if len(port_scan_tracker[src_ip]["ports"]) >= PORT_SCAN_THRESHOLD:
            send_alert(f"From {src_ip} on ports: {list(port_scan_tracker[src_ip]['ports'])}", "port_scan", src_ip, os_guess)
            del port_scan_tracker[src_ip]

    if packet.haslayer(Raw):
        payload = packet['Raw'].load
        for malicious_string in MALICIOUS_STRINGS:
            if malicious_string in payload.lower():
                send_alert(f"From {src_ip}: {payload.lower().decode(errors='ignore')[:50]}...", "malicious_payload", src_ip, os_guess)
                break

def sniff_packets():
    """Starts the packet sniffing process."""
    global is_sniffing_active, active_interface
    
    if is_sniffing_active:
        print(f"{Fore.YELLOW}Packet sniffing is already running.{Style.RESET_ALL}")
        return

    is_sniffing_active = True
    print(f"{Fore.GREEN}Starting packet sniffing on interface: {active_interface}{Style.RESET_ALL}\n")
    try:
        bpf_filter = "tcp or udp or icmp"
        sniff(iface=active_interface, filter=bpf_filter, prn=analyze_packet, store=0)
    except Exception as e:
        logging.error(f"Failed to start sniffing: {e}")
        print(f"\n{Fore.RED}ERROR: Failed to start sniffing. Please ensure you have:")
        print(f"1. Installed Npcap from https://nmap.org/npcap/ (Windows)")
        print(f"2. Run this script from an Administrator-level terminal.{Style.RESET_ALL}")
        user_choice = input(f"\n{Fore.YELLOW}Packet sniffing failed. Would you like to continue running the script? (y/n): {Style.RESET_ALL}").lower()
        if user_choice != 'y':
            exit()
    is_sniffing_active = False

def start_sniffing_thread():
    """Starts the sniffing process in a separate thread."""
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

def cleanup_trackers():
    """Periodically cleans up old entries in the trackers to save memory."""
    global ddos_tracker, port_scan_tracker, active_sessions
    now = time.time()
    
    for ip, tracker in list(ddos_tracker.items()):
        if now - tracker["last_seen"] > DDoS_TIME_WINDOW * 2:
            del ddos_tracker[ip]
    for ip, tracker in list(port_scan_tracker.items()):
        if now - tracker["last_seen"] > PORT_SCAN_TIME_WINDOW * 2:
            del port_scan_tracker[ip]
    for session_key, last_seen in list(active_sessions.items()):
        if now - last_seen > SESSION_TIMEOUT:
            del active_sessions[session_key]
    threading.Timer(60, cleanup_trackers).start()

def display_connections():
    """Displays a summary of listening and established connections."""
    print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}NETWORK CONNECTION STATUS:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*100}{Style.RESET_ALL}")
    listening_ports = []
    established_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr and conn.status == psutil.CONN_LISTEN:
            listening_ports.append(f"  {Fore.GREEN}[LISTEN]{Style.RESET_ALL} {conn.laddr.ip}:{conn.laddr.port} ({conn.pid if conn.pid else 'N/A'})")
        elif conn.laddr and conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
            established_connections.append(f"  {Fore.BLUE}[CONN]{Style.RESET_ALL} {conn.laddr.ip}:{conn.laddr.port} <-> {conn.raddr.ip}:{conn.raddr.port}")
    print(f"{Fore.LIGHTBLUE_EX}LISTENING PORTS ({len(listening_ports)}):{Style.RESET_ALL}")
    if listening_ports:
        for port in sorted(listening_ports):
            print(port)
    else:
        print(f"  {Fore.WHITE}No listening ports found.{Style.RESET_ALL}")
    print(f"\n{Fore.LIGHTBLUE_EX}ESTABLISHED CONNECTIONS ({len(established_connections)}):{Style.RESET_ALL}")
    if established_connections:
        for conn in sorted(established_connections):
            print(conn)
    else:
        print(f"  {Fore.WHITE}No established connections found.{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")

def send_email_report(is_periodic=False):
    """Generates a summary report from the queue and sends it via email."""
    global report_queue, is_periodic_reporting_active, EMAIL_USERNAME, EMAIL_PASSWORD
    
    if not ensure_email_credentials():
        return
        
    message_subject = "NetEye Security Report"
    report_content = f"NetEye Security Report - {time.ctime()}\n\n"
    
    if not report_queue:
        report_content += "No security events detected in the last "
        if is_periodic:
            report_content += f"{REPORTING_INTERVAL // 60} minutes."
        else:
            report_content += "since the last report."
    else:
        report_content += "The following security events were detected:\n\n"
        while report_queue:
            report_content += f"{report_queue.popleft()}\n"
    
    try:
        msg = EmailMessage()
        msg.set_content(report_content)
        msg['Subject'] = message_subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = EMAIL_USERNAME

        with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"\n{Fore.GREEN}[REPORT]{Style.RESET_ALL} Summary report sent successfully!")
    except Exception as e:
        print(f"\n{Fore.RED}[REPORT FAILED]{Style.RESET_ALL} Failed to send email report: {e}")

    if is_periodic:
        threading.Timer(REPORTING_INTERVAL, send_email_report, args=[True]).start()

def start_periodic_reporting():
    """Starts the periodic email reporting timer."""
    global is_periodic_reporting_active
    if not ensure_email_credentials():
        return
    if is_periodic_reporting_active:
        print(f"{Fore.YELLOW}Periodic reporting is already active.{Style.RESET_ALL}")
        return
    is_periodic_reporting_active = True
    print(f"{Fore.GREEN}Starting periodic email reporting. A report will be sent every {REPORTING_INTERVAL // 60} minutes.{Style.RESET_ALL}")
    send_email_report(is_periodic=True)

def send_custom_email():
    """Prompts the user for a recipient, subject, and message, and sends a custom email."""
    if not ensure_email_credentials():
        return
    
    recipient = input(f"{Fore.YELLOW}Enter recipient email address: {Style.RESET_ALL}")
    subject = input(f"{Fore.YELLOW}Enter email subject: {Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}Enter email body (type 'END' on a new line to finish):{Style.RESET_ALL}")
    message_lines = []
    while True:
        line = input()
        if line.strip().upper() == 'END':
            break
        message_lines.append(line)
    message_body = "\n".join(message_lines)

    try:
        msg = EmailMessage()
        msg.set_content(message_body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = recipient

        with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"\n{Fore.GREEN}[EMAIL]{Style.RESET_ALL} Custom email sent successfully to {recipient}!")
    except Exception as e:
        print(f"\n{Fore.RED}[EMAIL FAILED]{Style.RESET_ALL} Failed to send email: {e}")

def update_local_ip_interactive():
    """Allows the user to interactively update the LOCAL_IP."""
    global LOCAL_IP, active_interface, config
    
    if not active_interface:
        print(f"{Fore.RED}Interface not detected. Please restart the script.{Style.RESET_ALL}")
        return
    
    try:
        interface_addrs = psutil.net_if_addrs()[active_interface]
        local_ips_on_interface = [addr.address for addr in interface_addrs if addr.family == socket.AF_INET]
        
        print(f"\n{Fore.YELLOW}The current LOCAL_IP is: {Style.BRIGHT}{LOCAL_IP}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}The actual IP addresses for {active_interface} are: {local_ips_on_interface}{Style.RESET_ALL}")
        
        user_choice = input(f"{Fore.YELLOW}Please enter the correct LOCAL_IP or press Enter to cancel: {Style.RESET_ALL}")
        if user_choice and user_choice in local_ips_on_interface:
            LOCAL_IP = user_choice
            print(f"{Fore.GREEN}LOCAL_IP updated to {LOCAL_IP} for this session.{Style.RESET_ALL}")
            save_choice = input(f"{Fore.YELLOW}Would you like to save this IP to config.ini for future use? (y/n): {Style.RESET_ALL}").lower()
            if save_choice == 'y':
                config.set('Network', 'local_ip', LOCAL_IP)
                with open(CONFIG_FILE, 'w') as configfile:
                    config.write(configfile)
                print(f"{Fore.GREEN}config.ini has been updated.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid IP entered. LOCAL_IP remains unchanged.{Style.RESET_ALL}")
    except KeyError:
        print(f"\n{Fore.RED}Could not find addresses for interface '{active_interface}' during validation.{Style.RESET_ALL}")

def view_configuration():
    """Displays the current configuration settings."""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}CURRENT CONFIGURATION:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
    for section in config.sections():
        print(f"[{Fore.BLUE}{section}{Style.RESET_ALL}]")
        for key, value in config.items(section):
            print(f"  {Fore.GREEN}{key:<20}{Style.RESET_ALL} = {value}")
    print(f"\n{Fore.YELLOW}Active Interface: {active_interface}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Current LOCAL_IP: {LOCAL_IP}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

def perform_nmap_scan():
    """Prompts for a target IP/subnet and performs a basic network scan using Nmap."""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}NMAP Network Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
    target = input(f"{Fore.YELLOW}Enter target IP address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24): {Style.RESET_ALL}")
    
    if not target:
        print(f"{Fore.RED}No target provided. Aborting scan.{Style.RESET_ALL}")
        return
        
    print(f"{Fore.GREEN}Starting Nmap scan on {target}... This may take a moment.{Style.RESET_ALL}")
    
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sT -p 1-1024')
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}Scan Results for {target}:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

        for host in nm.all_hosts():
            print(f"  {Fore.GREEN}Host: {Style.NORMAL}{host} ({nm[host].hostname()}){Style.RESET_ALL}")
            if 'tcp' in nm[host]:
                for proto in nm[host]['tcp']:
                    port_status = nm[host]['tcp'][proto]
                    print(f"    {Fore.BLUE}Port {proto:<5}{Style.RESET_ALL} | {Fore.MAGENTA}State:{Style.NORMAL} {port_status['state']:<10} | {Fore.CYAN}Name:{Style.NORMAL} {port_status['name']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    except nmap.nmap.PortScannerError as e:
        print(f"{Fore.RED}Nmap Scan Error: Please ensure Nmap is installed and the command is run with administrator privileges.{Style.RESET_ALL}")
        print(f"Details: {e}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred during the scan: {e}{Style.RESET_ALL}")
        
    print(f"\n{Fore.GREEN}Scan complete.{Style.RESET_ALL}")

# --- Sub-Menu Functions ---
def handle_offensive_menu():
    """Handles the offensive tools sub-menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}Offensive Tools{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
        print(f"1. Start ARP Spoofing Attack")
        print(f"2. Start Man-in-the-Middle Attack")
        print(f"3. Start DNS Spoofing Attack")
        print(f"0. Back to Main Menu")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        choice = input(f"{Fore.YELLOW}Please choose an option (1-3, 0 to go back): {Style.RESET_ALL}")
        
        if choice == '1':
            arp_spoof.start_arp_spoofing()
        elif choice == '2':
            mitm_spoof.start_mitm_attack()
        elif choice == '3':
            dns_spoof.start_dns_spoofing()
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
        input(f"{Fore.MAGENTA}\nPress Enter to continue...{Style.RESET_ALL}")
        
def handle_defensive_menu():
    """Handles the defensive tools sub-menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{Style.BRIGHT}Defensive Tools{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
        print(f"1. Start Packet Sniffing {Fore.GREEN}(Status: {'Active' if is_sniffing_active else 'Inactive'}){Style.RESET_ALL}")
        print(f"2. Display Current Connections")
        print(f"3. Start ARP Spoofing Defender")
        print(f"4. Start DNS Spoofing Defender")
        print(f"5. Perform a Network Scan (Nmap)")
        print(f"6. Start Periodic Email Reports {Fore.GREEN}(Status: {'Active' if is_periodic_reporting_active else 'Inactive'}){Style.RESET_ALL}")
        print(f"0. Back to Main Menu")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        choice = input(f"{Fore.YELLOW}Please choose an option (1-6, 0 to go back): {Style.RESET_ALL}")
        
        if choice == '1':
            start_sniffing_thread()
        elif choice == '2':
            display_connections()
        elif choice == '3':
            arp_defender.start_arp_defender()
        elif choice == '4':
            dns_defender.start_dns_defender()
        elif choice == '5':
            perform_nmap_scan()
        elif choice == '6':
            start_periodic_reporting()
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
        input(f"{Fore.MAGENTA}\nPress Enter to continue...{Style.RESET_ALL}")

def handle_utilities_menu():
    """Handles the general utilities sub-menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}Configuration & Utilities{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
        print(f"1. Update LOCAL_IP")
        print(f"2. View Configuration")
        print(f"3. Send a Custom Email Message")
        print(f"4. Force Send a Report Now")
        print(f"0. Back to Main Menu")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        choice = input(f"{Fore.YELLOW}Please choose an option (1-4, 0 to go back): {Style.RESET_ALL}")

        if choice == '1':
            update_local_ip_interactive()
        elif choice == '2':
            view_configuration()
        elif choice == '3':
            send_custom_email()
        elif choice == '4':
            send_email_report(is_periodic=False)
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
        input(f"{Fore.MAGENTA}\nPress Enter to continue...{Style.RESET_ALL}")


def display_main_menu():
    """Prints the main menu to the console."""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}NetEye Main Menu{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
    print(f"1. Offensive Tools (Attack)")
    print(f"2. Defensive Tools (Monitor)")
    print(f"3. Configuration & Utilities")
    print(f"0. Exit")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")


def main():
    """Main function to start NetEye with a menu interface."""
    global active_interface
    
    os.system('cls' if os.name == 'nt' else 'clear')

    neteye_art = text2art("NetEye", font="block")
    hunter_art = "Coded by: Midnight Hunter"
    
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print(neteye_art)
    print(f"{Style.DIM}{'':>60}Advanced Network Monitoring Tool{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'':>70}{hunter_art}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*100}{Style.RESET_ALL}")
    
    active_interface = find_active_interface()
    if not active_interface:
        print(f"{Fore.RED}Exiting script due to interface detection failure.{Style.RESET_ALL}")
        exit()
    
    # Start cleanup thread in the background
    threading.Timer(60, cleanup_trackers).start()

    while True:
        display_main_menu()
        choice = input(f"{Fore.YELLOW}Please choose an option (1-3, 0 to exit): {Style.RESET_ALL}")

        if choice == '1':
            handle_offensive_menu()
        elif choice == '2':
            handle_defensive_menu()
        elif choice == '3':
            handle_utilities_menu()
        elif choice == '0':
            print(f"{Fore.GREEN}Exiting NetEye. Goodbye!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter a number between 0 and 3.{Style.RESET_ALL}")
        
if __name__ == "__main__":
    main()