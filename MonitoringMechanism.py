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
import shutil
import stat

# Register the signal handler for graceful script termination
def graceful_exit(signum, frame):
    print("\\nInterrupt signal received. Exiting gracefully...")
    cursor.close()
    connection.close()
    exit(0)

signal.signal(signal.SIGINT, graceful_exit)
signal.signal(signal.SIGTERM, graceful_exit)

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

# global error counters
error_counters = {
    'hash_mismatch': 0,
    'not_in_db': 0,
    'file_read_error': 0,
    'database_error': 0,
    'other_errors': 0,
    'malware_alert': 0,
    'database_error_malware': 0
}

def get_quarantine_dir(config_file='directories_config.json'):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            os_type = platform.system()
            return config['QuarantineDir'].get(os_type)
    except KeyError:
        print("Quarantine directory not defined for the current OS in the configuration file.")
        return None
    except FileNotFoundError:
        print(f"Configuration file not found: {config_file}")
        return None
    except json.JSONDecodeError:
        print(f"Error reading JSON from file: {config_file}")
        return None

QUARANTINE_DIR = "D:\IFT 520\FIM\Source"

def quarantine_file(file_path):
    try:
        # Construct the path in the quarantine directory with a different extension
        # e.g., changing '.exe' to '.quarantined'
        base_name = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, base_name + ".quarantined")

        # Move the file to the quarantine directory
        shutil.move(file_path, quarantine_path)

        # Modify permissions to prevent execution (e.g., make the file read-only)
        os.chmod(quarantine_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        print(f"\nFile quarantined: {file_path} -> {quarantine_path}")
        error_queue.put(f"File quarantined: {file_path} -> {quarantine_path}")
    except Exception as e:
        print(f"\nError quarantining file {file_path}: {e}")
        error_queue.put(f"Error quarantining file {file_path}: {e}")

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError) as e:
        error_queue.put(f"Error ({type(e).__name__}) processing {file_path}: {str(e)}")
        error_counters['file_read_error'] += 1
        return None
    except Exception as e:
        error_queue.put(f"Unexpected error processing {file_path}: {str(e)}")
        error_counters['other_errors'] += 1
        return None        

def check_files_integrity(files_batch):
    connection = pyodbc.connect(get_connection_string(connection_details))
    thread_cursor = connection.cursor()
    hashes = [(f, compute_sha256(f)) for f in files_batch]
    hashes = [(f, h) for f, h in hashes if h]

    CHUNK_SIZE = 100
    for i in range(0, len(hashes), CHUNK_SIZE):
        chunk = hashes[i:i+CHUNK_SIZE]
        try:
            thread_cursor.execute("SELECT file_path, file_hash_sha256 FROM FileBaselines WHERE file_path_hash IN ({0})"
                                  .format(", ".join(["HASHBYTES('SHA2_256', ?)"] * len(chunk))), [f[0] for f in chunk])
            results = {row.file_path: row.file_hash_sha256 for row in thread_cursor.fetchall()}
            for (file, hash) in chunk:
                if file not in results:
                    error_queue.put(f"File not found in DB: {file}")
                    error_counters['not_in_db'] += 1
                    try:
                        thread_cursor.execute("SELECT 1 FROM MalwareHashes WHERE SHA256Hash = ?", hash)
                        if thread_cursor.fetchone() is not None:
                            error_queue.put(f"Malware detected! File locaiton: {file}")
                            quarantine_file(file)
                            error_counters['malware_alert'] += 1
                    except Exception as e:
                        error_counters['database_error_malware'] += 1
                        error_queue.put(f"Database Malware read error: {str(e)}")
                elif hash != results[file]:
                    error_queue.put(f"Hash mismatch for {file}")
                    error_counters['hash_mismatch'] += 1
                    try:
                        thread_cursor.execute("SELECT 1 FROM MalwareHashes WHERE SHA256Hash = ?", hash)
                        if thread_cursor.fetchone() is not None:
                            error_queue.put(f"Malware detected! File locaiton: {file}")
                            quarantine_file(file)
                            error_counters['malware_alert'] += 1
                    except Exception as e:
                        error_counters['database_error_malware'] += 1
                        error_queue.put(f"Database Malware read error: {str(e)}")
        except Exception as e:
            error_queue.put(f"Database error: {str(e)}")
            error_counters['database_error'] += 1
    thread_cursor.close()
    connection.close()

def get_connection_string(details):
    if details['auth_method'] == "windows":
        return f'DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={details["DB_SERVER"]};DATABASE={details["DB_DATABASE"]};Trusted_Connection=yes;LoginTimeout=30;TrustServerCertificate=yes;'
    else:
        return f'DRIVER={{SQL Server}};SERVER={details["DB_SERVER"]};DATABASE={details["DB_DATABASE"]};UID={details["DB_USERNAME"]};PWD={details["DB_PASSWORD"]};'

connection_details = get_connection_details()
try:
    connection = pyodbc.connect(get_connection_string(connection_details))
    cursor = connection.cursor()
except pyodbc.OperationalError as oe:
    print(f"Failed to connect to the database: {str(oe)}")
    exit()

all_files = []
for target in TARGETS:
    for root, dirs, files in os.walk(target):
        for file in files:
            all_files.append(os.path.join(root, file))

error_queue = queue.Queue()

BATCH_SIZE_INTEGRITY = 10
with concurrent.futures.ThreadPoolExecutor() as executor:
    list(tqdm(executor.map(check_files_integrity, [all_files[i:i+BATCH_SIZE_INTEGRITY] for i in range(0, len(all_files), BATCH_SIZE_INTEGRITY)]), total=len(all_files)//BATCH_SIZE_INTEGRITY, desc="Checking files", unit="batch"))

# While logging the errors, we will only write them to the file and not print them to the console
while not error_queue.empty():
    error = error_queue.get()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open("monitoring_log.txt", "a", encoding='utf-8') as log_file:
        log_file.write(f"[{timestamp}] {error}\n")

# Print the error summary
print("\nError Summary:")
print(f"Malware Detected: {error_counters['malware_alert']}")
print(f"Hash mismatches: {error_counters['hash_mismatch']}")
print(f"Files not found in DB: {error_counters['not_in_db']}")
print(f"File permission read errors: {error_counters['file_read_error']}")
print(f"Database errors: {error_counters['database_error']}")
print(f"Malware Database read errors: {error_counters['database_error_malware']}")
print(f"Other errors: {error_counters['other_errors']}")
print("\nCheck monitoring_log.txt for details.")

# Close the main database connection
cursor.close()
connection.close()