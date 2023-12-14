import os
import pyodbc
import hashlib
import platform
import json
from GetConnectionDetails import get_connection_details
from tqdm import tqdm
import concurrent.futures
import queue
import signal
from datetime import datetime

def graceful_exit(signum, frame):
    # Handles graceful script termination.
    print("Interrupt signal received. Exiting gracefully...")
    cursor.close()
    connection.close()
    exit(0)

# Register the signal handler for graceful exit
signal.signal(signal.SIGINT, graceful_exit)
signal.signal(signal.SIGTERM, graceful_exit)

# Reading Malware Hashes from File
def read_sha256_hashes(file_path):
    hashes = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line.startswith('#'):  # Check if the line doesn't start with '#'
                hashes.append(line)
    return hashes

# Inserting Hashes into the Database (Malware Hashes Table) in Batches
def insert_hashes_into_db_in_batches(cursor, hashes, batch_size=1000):
    total = len(hashes)
    with tqdm(total=total, desc="Creating Malware Hashes Table", unit="hash") as pbar:
        for i in range(0, total, batch_size):
            batch = hashes[i:i + batch_size]
            values = [(hash_value, datetime.today()) for hash_value in batch]
            try:
                cursor.executemany("INSERT INTO MalwareHashes (SHA256Hash, DateAdded) VALUES (?, ?)", values)
            except Exception as e:
                print(f"Error in batch {i//batch_size}: {e}")
            else:
                cursor.connection.commit()
                pbar.update(len(batch))  # Update the progress bar by the number of hashes processed           

def get_targets():
    try:
        # look for directories_config.json first.
        with open("directories_config.json", "r") as file:
            config = json.load(file)
            return config.get(platform.system(), [])
    except FileNotFoundError:
        # Return directories to be monitored based on the operating system.
        if platform.system() == "Windows":
            return ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)"]
        elif platform.system() == "Linux":
            return ["/bin", "/etc", "/lib", "/usr", "/var"]
        elif platform.system() == "Darwin":  # macOS
            return ["/bin", "/etc", "/usr", "/var"]
        else:
            raise SystemError("Unsupported OS detected!")

TARGETS = get_targets()

# Global error counters
error_counters = {
    "PermissionError": 0,
    "FileNotFoundError": 0,
    "IsADirectoryError": 0,
    "DatabaseError": 0
}

def compute_sha256(file_path):
    # Compute and return the SHA-256 hash of a given file.
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        error_counters["PermissionError"] += 1
        error_queue.put(f"Permission denied for {file_path}. Skipping...")
        return None
    except FileNotFoundError:
        error_counters["FileNotFoundError"] += 1
        error_queue.put(f"File not found: {file_path}. Skipping...")
        return None
    except IsADirectoryError:
        error_counters["IsADirectoryError"] += 1
        error_queue.put(f"Expected a file but found a directory: {file_path}. Skipping...")
        return None

def batched_db_update(file_batch):
    # Perform batched database update for a group of files.
    try:
        for file, hash_val in file_batch:
            cursor.execute('''
            IF EXISTS (SELECT 1 FROM FileBaselines WHERE file_path_hash = HASHBYTES('SHA2_256', ?))
                UPDATE FileBaselines SET file_hash_sha256 = ?, last_checked = CURRENT_TIMESTAMP WHERE file_path = ?
            ELSE
                INSERT INTO FileBaselines (file_path, file_hash_sha256, last_checked, last_modified)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
            ''', (file, hash_val, file, file, hash_val))
        connection.commit()
    except pyodbc.OperationalError as oe:
        error_counters["DatabaseError"] += 1
        error_queue.put(f"Database operational error: {str(oe)}")

def process_files(files):
    # Compute hash for files and add them to the database update queue in batches.
    batch = []
    for file in files:
        hash_val = compute_sha256(file)
        if hash_val:
            batch.append((file, hash_val))
        if len(batch) == BATCH_SIZE:
            db_queue.put(batch)
            batch = []
    if batch:
        db_queue.put(batch)

def get_connection_string(details):
    # Construct database connection string based on the provided details.
    if details['auth_method'] == "windows":
        return f'DRIVER={{SQL Server}};SERVER={details["DB_SERVER"]};DATABASE={details["DB_DATABASE"]};Trusted_Connection=yes;'
    else:
        return f'DRIVER={{SQL Server}};SERVER={details["DB_SERVER"]};DATABASE={details["DB_DATABASE"]};UID={details["DB_USERNAME"]};PWD={details["DB_PASSWORD"]};'

# Fetch database connection details and establish connection
connection_details = get_connection_details()
connection_string = get_connection_string(connection_details)
try:
    connection = pyodbc.connect(connection_string)
    cursor = connection.cursor()
except pyodbc.OperationalError as oe:
    print(f"Failed to connect to the database: {str(oe)}")
    exit()

# Define the path to your SHA256 hash file
sha256_file_path = 'full_sha256.txt'

# Read hashes from the file
sha256_hashes = read_sha256_hashes(sha256_file_path)

# Insert hashes into the database in batches
insert_hashes_into_db_in_batches(cursor, sha256_hashes)

# Compile a list of all files from the target directories
all_files = []
for target in TARGETS:
    for root, dirs, files in os.walk(target):
        for file in files:
            all_files.append(os.path.join(root, file))

# Define a batch size for database operations
BATCH_SIZE = 100

# Instantiate queues for database operations and error logging
db_queue = queue.Queue()
error_queue = queue.Queue()

# Use ThreadPoolExecutor for parallel file processing
with concurrent.futures.ThreadPoolExecutor() as executor:
    list(tqdm(executor.map(process_files, [all_files[i:i+BATCH_SIZE] for i in range(0, len(all_files), BATCH_SIZE)]), total=len(all_files)//BATCH_SIZE, desc="Processing files", unit="batch"))

# Process the database update batches
with tqdm(total=len(all_files) // BATCH_SIZE, desc="Uploading to Database", unit="batch") as pbar:
    while not db_queue.empty():
        batch = db_queue.get()
        batched_db_update(batch)
        pbar.update(1)

# Log any errors
print("\nError Summary:")
for error_type, count in error_counters.items():
    if count:
        print(f"{error_type}: {count} occurrences")
print("\nCheck error_log.txt for details.")

while not error_queue.empty():
    error = error_queue.get()
    with open("error_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.now()}] {error}\n")

# Close the database connection
cursor.close()
connection.close()