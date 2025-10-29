"""
Process Monitoring Module for Host Intrusion Detection System (HIDS)

This module continuously monitors system processes, tracking:
- Process creation and termination
- CPU and memory usage
- Thread count
- User context and privileges
- Resource consumption alerts

Key Features:
- Tracks all running processes with detailed metrics
- Filters processes using an ignore list
- Classifies resource usage with alert levels
- Stores data in SQLite database for analysis
- Handles process permission issues gracefully


Author: Jean L. González Milán
"""

import ctypes
import getpass
import psutil
import os
from datetime import datetime
import sqlite3

# ==============================
# CONFIGURATION SECTION
# ==============================

# File containing processes to ignore (one per line)
ignore_list_file = 'ignore_process_list.txt'

# Alert thresholds (percentage)
CRITICAL_THRESHOLD = 80  # Critical alert threshold for CPU/memory
MODERATE_THRESHOLD = 50  # Moderate alert threshold
LIGHT_THRESHOLD = 20     # Light alert threshold

# ==============================
# INITIALIZATION SECTION
# ==============================

# Load process ignore list
ignore_list = set()
if os.path.exists(ignore_list_file):
    with open(ignore_list_file, 'r') as file:
        ignore_list = set(line.strip() for line in file if line.strip())

# Dictionary to track process start times (future enhancement)
process_start_times = {}

# ==============================
# UTILITY FUNCTIONS
# ==============================

def is_admin():
    """
    Check if the current user has administrator privileges.
    
    Returns:
        bool: True if user is admin, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_executable_id(cursor, conn, name, path):
    """
    Get or create an executable ID in the database.
    
    Args:
        cursor: Database cursor object
        conn: Database connection object
        name: Executable name
        path: Full executable path
        
    Returns:
        int: The executable_id from database
    """
    cursor.execute(
        "SELECT executable_id FROM Executables WHERE executable_name = ? AND executable_path = ?", 
        (name, path)
    )
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        cursor.execute(
            "INSERT INTO Executables (executable_name, executable_path) VALUES (?, ?)", 
            (name, path)
        )
        conn.commit()
        return cursor.lastrowid

# ==============================
# MAIN MONITORING FUNCTION
# ==============================

def main():
    """
    Main process monitoring loop.
    
    Continuously:
    1. Scans all running processes
    2. Collects performance metrics
    3. Applies alert thresholds
    4. Stores data in database
    5. Handles exceptions gracefully
    
    Exits on keyboard interrupt or critical error.
    """
    # Initialize database connection
    conn = sqlite3.connect('hids_database.db')
    cursor = conn.cursor()
    
    try:
        while True:
            for pid in psutil.pids():
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():  # Optimize performance
                        # Get process metadata
                        executable_path = p.exe()
                        executable_name = p.name()
                        user_role = "Admin" if is_admin() else "Standard User"
                        start_time = datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Skip ignored processes with low resource usage
                        if p.name() in ignore_list or executable_path in ignore_list:
                            cpu_usage = p.cpu_percent(interval=0.1)
                            memory_usage = p.memory_info().rss / psutil.virtual_memory().total * 100
                            if cpu_usage < LIGHT_THRESHOLD and memory_usage < LIGHT_THRESHOLD:
                                continue
                        
                        # Determine process status
                        if p.is_running():
                            end_time = "N/A"
                            status = p.status()
                        else:
                            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            status = "terminated"
                        
                        # Store process data
                        executable_id = get_executable_id(cursor, conn, executable_name, executable_path)
                        cursor.execute("""
                            INSERT INTO Processes (
                                executable_id, 
                                start_time, 
                                end_time, 
                                status, 
                                user, 
                                role
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            executable_id, 
                            start_time, 
                            end_time, 
                            status, 
                            getpass.getuser(), 
                            user_role
                        ))
                        conn.commit()
                        process_id = cursor.lastrowid
                        
                        # Get resource metrics
                        cpu_usage = p.cpu_percent(interval=0.1)
                        memory_usage = p.memory_info().rss / psutil.virtual_memory().total * 100
                        thread_count = p.num_threads()
                        
                        # Determine alert level
                        if cpu_usage > CRITICAL_THRESHOLD or memory_usage > CRITICAL_THRESHOLD:
                            usage_alert = "CRITICAL"
                        elif cpu_usage > MODERATE_THRESHOLD or memory_usage > MODERATE_THRESHOLD:
                            usage_alert = "MODERATE"
                        elif cpu_usage > LIGHT_THRESHOLD or memory_usage > LIGHT_THRESHOLD:
                            usage_alert = "LIGHT"
                        else:
                            usage_alert = "NORMAL"
                            
                        # Store resource usage
                        cursor.execute("""
                            INSERT INTO ResourceUsage (
                                process_id, 
                                cpu_usage, 
                                ram_usage, 
                                thread_count, 
                                usage_level
                            ) VALUES (?, ?, ?, ?, ?)
                        """, (
                            process_id, 
                            cpu_usage, 
                            memory_usage, 
                            thread_count, 
                            usage_alert
                        ))
                        conn.commit()
                
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue  # Skip processes we can't access
                except Exception as e:
                    print(f"Error processing PID {pid}: {e}")

    except KeyboardInterrupt:
        print("\nProcess Monitor stopped by user.")
    finally:
        conn.close()
        print("Database connection closed. Exiting...")

if __name__ == "__main__":
    print("Starting Process Monitor...")
    print(f"Ignoring {len(ignore_list)} processes from ignore list")
    print("Press Ctrl+C to stop monitoring")
    main()