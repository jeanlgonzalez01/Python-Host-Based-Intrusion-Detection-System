"""
File System Monitoring Module for Host Intrusion Detection System (HIDS)

This module provides comprehensive file system monitoring capabilities including:
- Initial directory scanning
- Real-time monitoring of file changes (create/modify/move/delete)
- Checksum verification using CRC32
- Database logging of all file events
- User privilege tracking

Key Features:
- Recursive directory monitoring
- File integrity checking
- Detailed event logging
- Admin/user privilege differentiation
- Thread-safe database operations

Author: Jean L. González Milán
"""

import ctypes
import os
import zlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import sqlite3

# Database connection with thread-safe option
conn = sqlite3.connect('hids_database.db', check_same_thread=False)
cursor = conn.cursor()

def insert_file(cursor, conn, filename, filepath, creation_time, modification_time, 
                deletion_time, checksum, user, role):
    """
    Inserts file metadata into the Files table.
    
    Args:
        cursor: Database cursor object
        conn: Database connection object
        filename: Name of the file
        filepath: Full path to the file
        creation_time: File creation timestamp
        modification_time: Last modification timestamp
        deletion_time: Deletion timestamp or "NULL"
        checksum: CRC32 checksum of file contents
        user: Operating system user
        role: "Admin" or "Standard User"
        
    Returns:
        None: Logs errors to console on failure
    """
    try:
        cursor.execute("""
            INSERT INTO Files(
                filename, 
                file_path, 
                creation_time, 
                modification_time, 
                deletion_time, 
                hash_value, 
                user, 
                role
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            filename, 
            filepath, 
            creation_time, 
            modification_time, 
            deletion_time, 
            checksum, 
            user, 
            role
        ))
        conn.commit()
    except Exception as e:
        print(f"Database error inserting file record: {e}")
        conn.rollback()

def insert_event(cursor, conn, event_type, event_time, file_id):
    """
    Logs a file system event to the Events table.
    
    Args:
        cursor: Database cursor object
        conn: Database connection object
        event_type: Type of event (e.g., "Creation", "Modified")
        event_time: Timestamp of the event
        file_id: Foreign key to the Files table
        
    Returns:
        None: Logs errors to console on failure
    """
    try:
        cursor.execute("""
            INSERT INTO Events(
                event_type, 
                event_time, 
                file_id
            ) VALUES(?, ?, ?)
        """, (event_type, event_time, file_id))
        conn.commit()
    except Exception as e:
        print(f"Database error inserting event record: {e}")
        conn.rollback()

def is_admin():
    """
    Checks if the current process has administrator privileges.
    
    Returns:
        bool: True if running as admin, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def calculate_crc32_checksum(filepath):
    """
    Calculates CRC32 checksum of a file's contents.
    
    Args:
        filepath: Path to the file to checksum
        
    Returns:
        str: 8-digit hexadecimal checksum or None on error
    """
    checksum = 0
    try:
        with open(filepath, 'rb') as file:
            while chunk := file.read(8192):  # Read in 8KB chunks
                checksum = zlib.crc32(chunk, checksum)
    except (FileNotFoundError, PermissionError) as e:
        print(f"File access error for {filepath}: {e}")
        return None
    return format(checksum & 0xFFFFFFFF, '08x')  # Format as 8-digit hex

def scan_directory(directories):
    """
    Recursively scans directories and logs all files to database.
    
    Args:
        directories (list): List of directory paths to scan
        
    Returns:
        list: File details for all scanned files
    """
    file_details = []
    try:
        for directory in directories:
            for root, _, files in os.walk(directory):
                for file in files:
                    role = "Admin" if is_admin() else "Standard User"
                    filepath = os.path.join(root, file)
                    
                    # Get file metadata
                    creation_time = datetime.fromtimestamp(
                        os.path.getctime(filepath)
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    
                    modified_time = datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    
                    checksum = calculate_crc32_checksum(filepath)
                    
                    if checksum:
                        # Insert file record
                        insert_file(
                            cursor, conn, 
                            file, filepath, 
                            creation_time, modified_time, 
                            "NULL", checksum, 
                            getpass.getuser(), role
                        )
                        
                        file_id = cursor.lastrowid
                        insert_event(
                            cursor, conn, 
                            "Scanned in directory", 
                            creation_time, 
                            file_id
                        )
                        
                        file_details.append({
                            "filename": file,
                            "file_path": filepath,
                            "creation_time": creation_time,
                            "last_modified_time": modified_time,
                            "checksum": checksum
                        })

    except Exception as e:
        print(f"Directory scanning error: {e}")
    return file_details

class FileEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler for file system changes.
    
    Tracks:
    - File creations
    - Modifications
    - Moves/renames
    - Deletions
    
    Prevents duplicate event processing.
    """
    
    processed_files = set()  # Tracks processed files to avoid duplicates
    
    def on_created(self, event):
        """Handles file creation events."""
        if event.is_directory:
            return
            
        filepath = event.src_path
        if filepath in self.processed_files:
            return
            
        self.processed_files.add(filepath)
        role = "Admin" if is_admin() else "Standard User"
        filename = os.path.basename(filepath)
        creation_time = datetime.fromtimestamp(
            os.path.getctime(filepath)
        ).strftime('%Y-%m-%d %H:%M:%S')
        checksum = calculate_crc32_checksum(filepath)
        
        if checksum:
            print(f"New file detected: {filename}")
            print(f"Location: {filepath}")
            print(f"Checksum: {checksum}, Created: {creation_time}")
            
            insert_file(
                cursor, conn,
                filename, filepath,
                creation_time, "NULL", "NULL",
                checksum, getpass.getuser(), role
            )
            
            file_id = cursor.lastrowid
            insert_event(
                cursor, conn,
                "Creation",
                creation_time,
                file_id
            )

    def on_modified(self, event):
        """Handles file modification events."""
        if event.is_directory:
            return
            
        filepath = event.src_path
        checksum = calculate_crc32_checksum(filepath)
        
        if checksum:
            filename = os.path.basename(filepath)
            modified_time = datetime.fromtimestamp(
                os.path.getmtime(filepath)
            ).strftime('%Y-%m-%d %H:%M:%S')
            role = "Admin" if is_admin() else "Standard User"
            
            print(f"File modified: {filename}")
            print(f"Location: {filepath}")
            print(f"Checksum: {checksum}, Modified: {modified_time}")
            
            # Update file record
            cursor.execute(
                "SELECT * FROM Files WHERE file_path = ?", 
                (filepath,)
            )
            if (result := cursor.fetchone()):
                insert_file(
                    cursor, conn,
                    filename, filepath,
                    result[3], modified_time, "NULL",
                    checksum, getpass.getuser(), role
                )
                
                file_id = cursor.lastrowid
                insert_event(
                    cursor, conn,
                    "Modified",
                    modified_time,
                    file_id
                )

    def on_moved(self, event):
        """Handles file move/rename events."""
        if event.is_directory:
            return
            
        new_path = event.dest_path
        checksum = calculate_crc32_checksum(new_path)
        
        if checksum:
            modified_time = datetime.fromtimestamp(
                os.path.getmtime(new_path)
            ).strftime('%Y-%m-%d %H:%M:%S')
            old_name = os.path.basename(event.src_path)
            new_name = os.path.basename(new_path)
            
            print(f"File renamed: {old_name} -> {new_name}")
            print(f"New location: {new_path}")
            print(f"Checksum: {checksum}, Modified: {modified_time}")
            
            # Update moved file record
            cursor.execute(
                "SELECT * FROM Files WHERE filename = ?", 
                (old_name,)
            )
            if (result := cursor.fetchone()):
                insert_file(
                    cursor, conn,
                    new_name, new_path,
                    result[3], modified_time, "NULL",
                    result[6], result[7], result[8]  # Original hash, user, role
                )
                
                file_id = cursor.lastrowid
                insert_event(
                    cursor, conn,
                    f"Renamed from {old_name} to {new_name}",
                    modified_time,
                    file_id
                )

    def on_deleted(self, event):
        """Handles file deletion events."""
        if event.is_directory:
            return
            
        filepath = event.src_path
        filename = os.path.basename(filepath)
        deletion_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"File deleted: {filename}")
        print(f"Location: {filepath}")
        
        # Mark file as deleted in database
        cursor.execute(
            "SELECT * FROM Files WHERE file_path = ?", 
            (filepath,)
        )
        if (result := cursor.fetchone()):
            insert_file(
                cursor, conn,
                filename, filepath,
                result[3], result[4], deletion_time,
                result[6], getpass.getuser(), result[8]
            )
            
            file_id = cursor.lastrowid
            insert_event(
                cursor, conn,
                "Deletion",
                deletion_time,
                file_id
            )

def monitor_directories(directories):
    """
    Starts continuous monitoring of specified directories.
    
    Args:
        directories (list): Paths to monitor recursively
        
    Returns:
        None: Runs until keyboard interrupt
    """
    # Initial directory scan
    scan_directory(directories)
    
    # Set up real-time monitoring
    event_handler = FileEventHandler()
    observer = Observer()
    
    for directory in directories:
        observer.schedule(event_handler, path=directory, recursive=True)
    
    observer.start()
    print("File monitoring active. Press Ctrl+C to terminate.")
    
    try:
        while True:  # Main monitoring loop
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()