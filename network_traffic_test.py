"""
Network Traffic Test Generator for HIDS (Host Intrusion Detection System)

This module generates simulated network traffic to test the intrusion detection system's
ability to identify and log traffic from blacklisted IP addresses.

Key Features:
- Loads IP blacklist from file
- Generates test packets from both blacklisted and legitimate IPs
- Simulates TCP traffic to common ports
- Provides visual feedback of test execution

Author: Jean L. González Milán
"""

from scapy.all import IP, TCP, UDP, send
import time

# Configuration Constants
BLACKLIST_FILE = "blacklist.txt"  # Path to IP blacklist file (one IP per line, # for comments)

def load_blacklist():
    """
    Loads and parses the IP address blacklist file.
    
    The blacklist file should contain:
    - One IP address per line
    - Lines starting with '#' are treated as comments
    - Empty lines are skipped
    
    Returns:
        set: A set of blacklisted IP addresses
        Prints status message about loaded IP count
    
    Raises:
        FileNotFoundError: Silently handled, returns empty set with warning message
    """
    try:
        with open(BLACKLIST_FILE, "r") as file:
            blacklist = {
                line.strip() 
                for line in file 
                if line.strip() and not line.startswith("#")
            }
        print(f"[Security] Loaded {len(blacklist)} blacklisted IP addresses")
        return blacklist
    except FileNotFoundError:
        print(f"[Warning] Blacklist file '{BLACKLIST_FILE}' not found. Proceeding with empty blacklist.")
        return set()

def send_test_packets():
    """
    Generates test network traffic to validate HIDS monitoring.
    
    Behavior:
    1. Loads current blacklist
    2. Generates TCP packets from mixed IPs (blacklisted and clean)
    3. Sends to destination port 80 (HTTP)
    4. Provides visual feedback of each sent packet
    
    Test IP Composition:
    - 192.168.1.10 (typically blacklisted)
    - 10.0.0.5 (typically blacklisted)
    - 192.168.1.11 (typically clean)
    - 172.16.0.3 (typically clean)
    
    Packet Details:
    - Source ports: Random high port (12345)
    - Destination port: 80 (HTTP)
    - Protocol: TCP
    - Delay: 1 second between packets
    """
    blacklisted_ips = load_blacklist()
    
    # Test IP addresses - first two typically blacklisted
    test_ips = [
        "192.168.1.10",  # Expected to be in blacklist
        "10.0.0.5",      # Expected to be in blacklist 
        "192.168.1.11",  # Expected clean IP
        "172.16.0.3"     # Expected clean IP
    ]
    
    # Generate and send test packets
    for ip in test_ips:
        # Create IP packet with TCP layer
        packet = IP(src=ip, dst="192.168.1.1") / TCP(sport=12345, dport=80)
        
        # Visual indicator of packet source status
        status = "[BLACKLISTED]" if ip in blacklisted_ips else "[CLEAN]"
        print(f"{status} Sending test packet from {ip}")
        
        send(packet)  # Send the constructed packet
        time.sleep(1)  # Throttle packet sending

if __name__ == "__main__":
    """
    Main execution block when run as standalone script.
    
    Prints startup banner and initiates test packet generation.
    """
    print("=== HIDS Network Traffic Test Generator ===")
    print("Starting simulated traffic generation...")
    print("Packets will be sent from both blacklisted and clean IPs")
    print("------------------------------------------")
    
    send_test_packets()
    
    print("\nTest sequence completed")
    print("Verify HIDS detected and logged blacklisted traffic")