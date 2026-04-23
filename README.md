# 🛡️ Python Host-Based Intrusion Detection System (HIDS)

A proof-of-concept **Host-Based Intrusion Detection System** built in Python, designed to monitor a Windows host for suspicious activity across three domains: file system integrity, process behavior, and network traffic. All events are logged to a local SQLite database and visualized through a real-time web dashboard.

> **Author:** Jean L. González Milán
> **Platform:** Windows | **Language:** Python 3.10+

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Dashboard](#-dashboard)
- [Database Schema](#-database-schema)
- [Project Structure](#-project-structure)
- [Known Limitations](#-known-limitations)

---

## ✨ Features

- **File System Monitoring** — Watches configured directories for file creations, modifications, renames, and deletions. Computes CRC32 checksums on every file to detect integrity changes.
- **Process Monitoring** — Continuously scans all running processes using `psutil`, tracking CPU usage, RAM consumption, thread count, and privilege level. Classifies resource usage into `NORMAL / LIGHT / MODERATE / CRITICAL` alert levels.
- **Network Traffic Monitoring** — Sniffs live network packets using Scapy and flags any traffic originating from IPs listed in a configurable blacklist.
- **Web Dashboard** — Flask-powered interface with user authentication, real-time system stats (CPU, RAM, network interfaces), and tabular views of all monitoring data.
- **Persistent Logging** — All events are stored in a local SQLite database for historical review.
- **Concurrent Operation** — Each subsystem runs as an independent OS process via Python's `multiprocessing` module, ensuring isolation and true parallelism.

---

## 🏗️ Architecture

```
main.py  (Orchestrator)
├── flask_app.py          → Web dashboard & REST API (port 5000)
├── file_monitor.py       → Watchdog-based file system monitor
├── process_monitor.py    → psutil-based process & resource monitor
├── network_monitor.py    → Scapy-based packet sniffer
└── network_traffic_test.py → Synthetic packet generator (for testing)
                  ↓
          hids_database.db  (SQLite — shared data store)
```

All subsystems write to the shared SQLite database. The Flask app reads from it to power the dashboard.

---

## ⚙️ Requirements

| Requirement | Notes |
|---|---|
| Windows 10 or later | Linux/macOS not supported (Windows API calls used) |
| Python 3.10+ | Walrus operator (`:=`) required |
| [Npcap](https://npcap.com) | Required by Scapy for raw packet capture |
| Administrator privileges | Required to run the packet sniffer |

### Python Dependencies

```bash
pip install flask psutil watchdog scapy
```

---

## 🚀 Installation

**1. Clone the repository**
```bash
git clone https://github.com/your-username/Python-Host-Based-Intrusion-Detection-System.git
cd Python-Host-Based-Intrusion-Detection-System
```

**2. Install Npcap**

Download and install from [https://npcap.com](https://npcap.com). Reboot if prompted.

**3. Install Python dependencies**
```bash
pip install flask psutil watchdog scapy
```

**4. Initialize the database**
```bash
python database.py
```
> ⚠️ This drops and recreates all tables. Do not re-run it after collecting data unless you want to reset the database.

**5. Configure the system** (see [Configuration](#-configuration))

**6. Launch as Administrator**
```bash
python main.py
```

**7. Open the dashboard**
```
http://127.0.0.1:5000
```

---

## 🔧 Configuration

### Monitored Directories — `main.py`

Edit the `directories_to_monitor` list to specify which paths the file monitor watches:

```python
directories_to_monitor = [
    r"C:\Users\YourUser\Desktop\test directory",
    r"C:\Windows\System32",   # example: monitor system files
]
```

### IP Blacklist — `blacklist.txt`

Add one IP address per line. Lines starting with `#` are comments:

```
# Known malicious hosts
192.168.1.10
10.0.0.5
```

### Process Ignore List — `ignore_process_list.txt`

Add process names (one per line) to exclude from routine logging. Ignored processes are still logged if their CPU or RAM usage exceeds 20%:

```
explorer.exe
svchost.exe
chrome.exe
```

### Alert Thresholds — `process_monitor.py`

```python
CRITICAL_THRESHOLD = 80   # % CPU or RAM
MODERATE_THRESHOLD = 50
LIGHT_THRESHOLD    = 20
```

---

## 🖥️ Usage

### Starting the System

Run as **Administrator** from the project root:

```bash
python main.py
```

All subsystems start concurrently. Output is printed to the console. Stop with `Ctrl+C`.

### Resetting the Database

```bash
python database.py
```

### Seeding Test Data

```bash
python databasetestvalues.py
```

### Running the Network Test (standalone)

```bash
python network_traffic_test.py
```

---

## 📊 Dashboard

Access the web dashboard at `http://127.0.0.1:5000`.

### Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `password` | Admin |
| `jean` | `password` | User |

> ⚠️ Change these credentials before using in any non-isolated environment.

### REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Dashboard HTML |
| `POST` | `/login` | Authenticate user |
| `GET` | `/memory_stats` | RAM usage (total, used, available, %) |
| `GET` | `/cpu_stats` | CPU usage % and thread count |
| `GET` | `/network_information` | Network interface status and speed |
| `GET` | `/file_monitor` | File events from `FilesView` |
| `GET` | `/process_monitor` | Process data from `ProcessesView` |
| `GET` | `/network_traffic` | All captured network traffic records |

---

## 🗄️ Database Schema

```
User              — Login credentials and roles
Files             — File metadata and checksums
Events            — File system event log (linked to Files)
Executables       — Unique executable paths
Processes         — Process lifecycle records
ResourceUsage     — CPU/RAM snapshots per process
NetworkTraffic    — Captured packets from blacklisted IPs

Views:
  FilesView       — Files JOIN Events (used by /file_monitor)
  ProcessesView   — Processes JOIN Executables JOIN latest ResourceUsage
```

---

## 📁 Project Structure

```
Python-Host-Based-Intrusion-Detection-System/
├── main.py                   # Entry point — spawns all subsystems
├── database.py               # Schema initialization
├── flask_app.py              # Web interface & REST API
├── file_monitor.py           # File system monitoring
├── process_monitor.py        # Process & resource monitoring
├── network_monitor.py        # Network packet sniffing
├── network_traffic_test.py   # Test packet generator
├── databasetestvalues.py     # Test data seeder
├── blacklist.txt             # Blacklisted IP addresses
├── ignore_process_list.txt   # Processes excluded from monitoring
├── static/
│   ├── css/style.ccs
│   └── js/script.js
└── templates/
    └── index.html
```

---

## ⚠️ Known Limitations

| Area | Issue |
|---|---|
| **Platform** | Windows only — uses `ctypes.windll` for admin detection |
| **Password Security** | SHA-256 without salting — use bcrypt/Argon2 for real deployments |
| **File Integrity** | CRC32 is not cryptographically secure — consider SHA-256 for production |
| **Database Concurrency** | SQLite file-locking may cause delays under heavy write load |
| **Network Coverage** | Only TCP/UDP over IP is logged; ICMP and ARP are not recorded |
| **Flask Debug Mode** | `debug=True` is set — disable before any non-local deployment |

---

## 📄 License

This project is a proof of concept for educational purposes.
