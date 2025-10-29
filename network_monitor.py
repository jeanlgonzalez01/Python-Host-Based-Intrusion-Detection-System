"""
Network Monitoring Module for Host Intrusion Detection System (HIDS)

This module provides network traffic monitoring capabilities, specifically:
- Packet sniffing and analysis
- Blacklist-based traffic filtering
- Suspicious traffic logging to SQLite database
- Real-time monitoring of TCP/UDP/IP traffic

Key Features:
- Monitors network traffic for blacklisted IP addresses
- Logs detailed packet information to database
- Tracks packet sizes and protocol information
- Provides real-time console output of suspicious traffic
Author: Jean L. González Milán
"""

import sqlite3
from scapy.all import sniff, ARP, TCP, UDP, IP
import datetime

# Database Configuration
# Using check_same_thread=False to allow multi-threaded access
conn = sqlite3.connect('hids_database.db', check_same_thread=False)
cursor = conn.cursor()

# Security Configuration
BLACKLIST_FILE = "blacklist.txt"  # Path to IP blacklist file (one IP per line)

def insert_file(cursor, conn, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, timestamp):
    """
    Inserts network traffic data into the database.
    
    Args:
        cursor: Database cursor object
        conn: Database connection object
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port number
        dst_port: Destination port number
        protocol: Network protocol (TCP/UDP)
        packet_size: Size of packet in bytes
        timestamp: Time of packet capture
        
    Returns:
        None: Logs errors to console and rolls back on failure
    """
    try:
        cursor.execute("""
            INSERT INTO NetworkTraffic(
                source_ip, 
                destination_ip, 
                source_port, 
                destination_port, 
                protocol, 
                packet_size, 
                timestamp
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, src_port, dst_port, protocol, packet_size, timestamp))
        conn.commit()
    except Exception as e:
        print(f"Database error: Failed to insert network record - {e}")
        conn.rollback()

def load_blacklist():
    """
    Loads and parses the IP address blacklist file.
    
    File Format:
    - One IP address per line
    - Lines starting with '#' are treated as comments
    - Empty lines are skipped
    
    Returns:
        set: A set of blacklisted IP addresses
    """
    try:
        with open(BLACKLIST_FILE, "r") as file:
            blacklist = {
                line.strip() 
                for line in file 
                if line.strip() and not line.startswith("#")
            }
        print(f"Security: Loaded {len(blacklist)} blacklisted IP addresses")
        return blacklist
    except FileNotFoundError:
        print(f"Warning: Blacklist file '{BLACKLIST_FILE}' not found. Monitoring all traffic.")
        return set()

def log_packet(packet, blacklist):
    """
    Analyzes and logs network packets from blacklisted sources.
    
    Processes:
    - IP packets
    - TCP/UDP protocols
    - Extracts key metadata
    - Logs to database and console
    
    Args:
        packet: Scapy packet object
        blacklist: Set of blacklisted IP addresses
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Process only IP packets
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Check against blacklist
        if src_ip in blacklist:
            dst_ip = packet[IP].dst
            protocol = None
            src_port, dst_port = None, None

            # Extract TCP-specific data
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

            # Extract UDP-specific data
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Calculate packet size
            packet_size = len(packet)

            # Database logging
            insert_file(
                cursor, conn, 
                src_ip, dst_ip, 
                src_port, dst_port, 
                protocol, packet_size, 
                timestamp
            )

            # Console output
            log_entry = (
                f"Suspicious traffic detected: "
                f"{timestamp} | {src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port} | {protocol} | "
                f"{packet_size} bytes"
            )
            print(log_entry)

def start_packet_sniffer():
    """
    Main entry point for network monitoring.
    
    Initializes:
    - Blacklist loading
    - Packet sniffing with callback
    - Real-time monitoring
    
    Usage:
    - Runs continuously until interrupted
    - Prints monitoring header on startup
    """
    print("Initializing network monitor...")
    print("Monitoring for blacklisted traffic sources")
    print("Format: timestamp | src_ip:port -> dst_ip:port | protocol | size")
    print("Press Ctrl+C to terminate monitoring")
    
    blacklist = load_blacklist()
    
    # Start sniffing with callback
    sniff(
        prn=lambda pkt: log_packet(pkt, blacklist),  # Packet handler
        store=False  # Don't store packets in memory
    )

# Example standalone execution
# if __name__ == "__main__":
#     start_packet_sniffer()