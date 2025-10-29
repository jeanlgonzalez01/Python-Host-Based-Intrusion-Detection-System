import sqlite3

# Connect to the SQLite database (or create it)
conn = sqlite3.connect('hids_database.db')
cursor = conn.cursor()

# Drop tables if they exist
cursor.execute("DROP TABLE IF EXISTS ResourceUsage;")
cursor.execute("DROP TABLE IF EXISTS NetworkTraffic;")
cursor.execute("DROP TABLE IF EXISTS Processes;")
cursor.execute("DROP TABLE IF EXISTS Executables;")
cursor.execute("DROP TABLE IF EXISTS Events;")
cursor.execute("DROP TABLE IF EXISTS Files;")
cursor.execute("DROP TABLE IF EXISTS User;")
cursor.execute("DROP VIEW IF EXISTS FilesView;")
cursor.execute("DROP VIEW IF EXISTS ProcessesView;")
# Vacuum the database to clean up space
conn.execute("VACUUM;")
# Create User Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS User (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
);
""")

# Create Files Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    creation_time TEXT,
    modification_time TEXT,
    deletion_time TEXT,
    hash_value TEXT,
    user TEXT,
    role TEXT
);
""")

# Create Events Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    event_time TEXT,
    file_id INTEGER,
    FOREIGN KEY (file_id) REFERENCES Files(file_id)
);
""")

# Create Executables Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Executables (
    executable_id INTEGER PRIMARY KEY AUTOINCREMENT,
    executable_name TEXT NOT NULL,
    executable_path TEXT NOT NULL
);
""")

# Create Processes Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Processes (
    process_id INTEGER PRIMARY KEY AUTOINCREMENT,
    executable_id INTEGER NOT NULL,
    start_time TEXT,
    end_time TEXT,
    status TEXT NOT NULL,
    user TEXT,
    role TEXT,
    FOREIGN KEY (executable_id) REFERENCES Executables(executable_id)
);
""")

# Create ResourceUsage Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS ResourceUsage (
    resource_usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id INTEGER NOT NULL,
    cpu_usage REAL,
    ram_usage REAL,
    thread_count INTEGER,
    usage_level TEXT,
    FOREIGN KEY (process_id) REFERENCES Processes(process_id)
);
""")

# Create NetworkTraffic Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS NetworkTraffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    packet_size INTEGER,
    timestamp TEXT
);
""")

# Create Files View
cursor.execute("""
CREATE VIEW IF NOT EXISTS FilesView AS
SELECT 
    f.file_id,
    f.filename,
    f.file_path,
    f.creation_time,
    f.modification_time,
    f.deletion_time,
    f.hash_value,
    e.event_type,
    e.event_time,
    f.user,
    f.role
FROM 
    Files f
LEFT JOIN 
    Events e ON f.file_id = e.file_id;
"""
)

# Create Processes View
cursor.execute("""
CREATE VIEW IF NOT EXISTS ProcessesView AS
SELECT 
    p.process_id,
    p.start_time,
    p.end_time,
    p.status,
    p.user,
    p.role,
    e.executable_id,
    e.executable_name,
    e.executable_path,
    r.resource_usage_id,
    r.cpu_usage,
    r.ram_usage,
    r.thread_count,
    r.usage_level
FROM 
    Processes p
LEFT JOIN 
    Executables e ON p.executable_id = e.executable_id
LEFT JOIN 
    ResourceUsage r ON p.process_id = r.process_id
WHERE 
    r.resource_usage_id = (SELECT MAX(resource_usage_id) FROM ResourceUsage WHERE process_id = p.process_id);

"""
)

cursor.execute("""
INSERT INTO User (username, password_hash, role) VALUES
('jean', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'user'),
('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'admin');
""")



# Commit changes and close the connection
conn.commit()
conn.close()

print("Database tables and Combined View created and vacuumed successfully.")
