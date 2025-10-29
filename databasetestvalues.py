import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('hids_database.db')
cursor = conn.cursor()

# Delete existing data (if necessary)
cursor.execute("DELETE FROM ResourceUsage;")
cursor.execute("DELETE FROM NetworkTraffic;")
cursor.execute("DELETE FROM Processes;")
cursor.execute("DELETE FROM Executables;")
cursor.execute("DELETE FROM Events;")
cursor.execute("DELETE FROM Files;")
cursor.execute("DELETE FROM User;")


# Insert Sample Data into User Table
cursor.execute("""
INSERT INTO User (username, password_hash, role) VALUES
('jean', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'user'),
('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'admin');
""")

# # Insert Sample Data into Files Table
# cursor.execute("""
# INSERT INTO Files (file_path, creation_time, modification_time, hash_value, user) VALUES
# ('C:\\Users\\Jean\\file1.txt', '2024-10-01 12:00:00', '2024-10-02 12:00:00', 'abcdef123456', 'Jean'),
# ('C:\\Users\\Jean\\file2.txt', '2024-10-03 14:00:00', NULL, '123456abcdef', 'Jean');
# """)

# # Insert Sample Data into Events Table
# cursor.execute("""
# INSERT INTO Events (event_type, event_time, file_id, user, role) VALUES
# ('Created', '2024-10-01 12:00:01', 1, 'Jean', 'user'),
# ('Modified', '2024-10-03 14:00:01', 2, 'Jean', 'user');
# """)

# # Insert Sample Data into Executables Table
# cursor.execute("""
# INSERT INTO Executables (executable_name, executable_path) VALUES
# ('app.exe', 'C:\\Program Files\\app.exe');
# """)

# # Insert Sample Data into Processes Table
# cursor.execute("""
# INSERT INTO Processes (executable_id, start_time, end_time, status,user, role) VALUES
# (1, '2024-10-04 09:00:00', '2024-10-04 09:30:00', 'stopped','Jean', 'user'),
# (1, '2024-10-04 10:00:00', NULL, 'running','Alex', 'admin');
# """)

# # Insert Sample Data into ResourceUsage Table
# cursor.execute("""
# INSERT INTO ResourceUsage (process_id, cpu_usage, ram_usage, thread_count, usage_level) VALUES
# (1, 20.5, 150.0, 3, 'light'),
# (2, 85.0, 300.0, 5, 'critical');
# """)

# # Insert Sample Data into NetworkTraffic Table
# cursor.execute("""
# INSERT INTO NetworkTraffic (source_ip, destination_ip, source_port, destination_port, protocol, packet_size, timestamp, user, port_type, request_method, payload_size, login_attempt, file_transfer_size) VALUES
# ('192.168.1.1', '192.168.1.2', 12345, 80, 'TCP', 512, '2024-10-05 10:00:00', 'Jean', 'inbound', 'GET', 200, 0, 0),
# ('192.168.1.3', '192.168.1.4', 54321, 443, 'TCP', 1024, '2024-10-05 10:01:00', 'Alex', 'outbound', 'POST', 500, 1, 0);
# """)

# Commit changes and close the connection

conn.commit()
conn.close()

print("Sample data inserted successfully.")
