"""
HIDS (Host Intrusion Detection System) Main Controller

This script serves as the main entry point for the HIDS application.
It initializes and coordinates all system components by running them
as separate parallel processes for concurrent operation.

Components Managed:
1. Flask web interface (for monitoring and visualization)
2. Process monitoring subsystem
3. File system monitoring subsystem
4. Network monitoring subsystem
5. Network traffic test utility (for demonstration/testing)

Author: Jean L. González Milán
"""

import getpass
from multiprocessing import Process
import flask_app
import process_monitor
import file_monitor
import network_monitor
import network_traffic_test

# Define directories to monitor for file changes
# Currently monitors a test directory on the user's desktop
# Note: In production, this should be configured to monitor critical system directories
directories_to_monitor = [
    f"C:\\Users\\{getpass.getuser()}\\Desktop\\test directory"
]

def run_network_test():
    """
    Executes network traffic test utility.
    
    This function generates test network packets for demonstration
    and testing purposes of the network monitoring subsystem.
    """
    network_traffic_test.send_test_packets()

def run_network_monitor():
    """
    Starts the network monitoring subsystem.
    
    Launches the packet sniffer to monitor and log all network traffic
    passing through the host system's interfaces.
    """
    network_monitor.start_packet_sniffer()

def run_flask_app():
    """
    Launches the Flask web interface.
    
    Starts the web-based monitoring dashboard with the following configuration:
    - debug=True: Enables Flask debug mode (disable in production)
    - use_reloader=False: Disables Flask reloader to avoid process conflicts
    """
    flask_app.app.run(debug=True, use_reloader=False)

def run_process_monitor():
    """
    Starts the process monitoring subsystem.
    
    Initiates continuous monitoring of system processes, tracking:
    - Process creation/termination
    - Resource usage (CPU, memory)
    - Execution statistics
    """
    process_monitor.main()

def run_file_monitor():
    """
    Starts the file system monitoring subsystem.
    
    Begins monitoring specified directories for:
    - File creations
    - Modifications
    - Deletions
    - Permission changes
    
    Args:
        directories_to_monitor: List of paths to monitor (configured at module level)
    """
    file_monitor.monitor_directories(directories_to_monitor)

if __name__ == "__main__":
    """
    Main execution block.
    
    Initializes and manages all system components as separate processes
    using Python's multiprocessing module for concurrent operation.
    """

    # Create separate processes for each system component
    flask_process = Process(target=run_flask_app)              # Web interface
    monitor_process = Process(target=run_process_monitor)      # Process monitoring
    file_monitor_process = Process(target=run_file_monitor)    # File system monitoring
    network_monitor_process = Process(target=run_network_monitor)  # Network monitoring
    network_test_process = Process(target=run_network_test)    # Network test utility

    # Start all component processes
    print("Starting HIDS system components...")
    flask_process.start()
    monitor_process.start()
    file_monitor_process.start()
    network_monitor_process.start()
    network_test_process.start()
    print("All system components started successfully")

    # Wait for all processes to complete (typically runs indefinitely)
    # Note: In normal operation, processes should run continuously until terminated
    flask_process.join()
    monitor_process.join()
    file_monitor_process.join()
    network_monitor_process.join()
    network_test_process.join()