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

You have two main options to install dependencies. It is **strongly recommended** to use a virtual environment for better package management.

---

#### Option A: Using a Virtual Environment (Recommended)

##### Why Use It?

1. **Isolation**: Keeps all required packages isolated from system Python and other projects.
2. **Avoid Conflicts**: Allows different projects to use different versions of the same libraries.
3. **Clean Setup**: You start with a minimal environment that contains only what your project needs.
4. **Reproducibility**: Makes it easier to reproduce environments across systems.

##### How to Set Up:

```bash
python -m venv venv
source venv/bin/activate     # On Linux/macOS
venv\Scripts\activate        # On Windows
pip install -r requirements.txt
```

---

#### Option B: Installing Dependencies Globally (Not Recommended)

```bash
pip install -r requirements.txt
```

##### Risks:

* Might interfere with other Python projects on your system.
* Harder to manage and debug version conflicts.
* May require `sudo` permissions on Linux/macOS.

---

## Configuration

You will need to configure `config.ini` to enable email alerts and detection settings. A sample configuration template will be provided in the repo. You'll be prompted for email credentials if using alerting.

---

## Running NetEye

Start the main script with:

```bash
python main.py
```

Use the menu interface to navigate Offensive Tools, Defensive Tools, and Utilities. Make sure you run as Administrator or with root privileges for full functionality.

---

## Disclaimer

This tool is intended for **educational and authorized network testing only**. The author is not responsible for misuse or any illegal activities carried out using this software.

---

## License

MIT License

---

Happy Hunting,
**Midnight Hunter**
