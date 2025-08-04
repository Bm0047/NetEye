# NetEye - Advanced Network Monitoring Tool

**Coded by: Midnight Hunter**

---

## Overview

NetEye is a powerful, modular Python-based network monitoring tool designed for both offensive and defensive security tasks. It provides comprehensive packet sniffing, intrusion detection, network scanning, ARP/DNS spoofing and defense, and customizable alerting through email notifications.

---

## Features

### Offensive Tools

* ARP Spoofing Attack
* Man-in-the-Middle (MITM) Attack
* DNS Spoofing Attack

### Defensive Tools

* Real-time Packet Sniffing with detection of suspicious connections, port scans, and DDoS attempts
* ARP Spoofing Defender
* DNS Spoofing Defender
* Network scanning via Nmap integration
* Display current network connections

### Utilities & Configuration

* Auto-detect active network interface and IP
* Interactive updating of local IP
* View and edit configuration settings
* Send custom email alerts and periodic summary reports

### Alerts & Reporting

* Color-coded console alerts and detailed logging to file (`neteye.log`)
* Email alerting with secure app-password authentication
* Periodic email summary reports with configurable intervals

---

## Prerequisites

Before installing and running NetEye, ensure you have the following:

* **Operating System:** Windows, Linux, or macOS
* **Python Version:** 3.7 or higher
* **Administrator/Root Privileges:** Required for packet sniffing and spoofing operations
* **Nmap:** Installed and accessible in your system's PATH
  Download from: [https://nmap.org/download.html](https://nmap.org/download.html)
* **Npcap (Windows Only):** For packet capture support
  Download from: [https://nmap.org/npcap/](https://nmap.org/npcap/)
* **Network Access:** You must have permission to monitor or attack the network you target.

---

## Installation

### 1. Clone or Download the Repository

```bash
git clone https://github.com/Bm0047/neteye.git
cd neteye
```
### 2. Install Python Dependencies

It is recommended to use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
Once activated, install the required Python packages using:

```bash
pip install -r requirements.txt
###  If you don’t have a requirements.txt file, create one with the following packages:

psutil
scapy
colorama
requests
art
python-nmap
getpass
