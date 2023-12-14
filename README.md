# FIMS
Cloud Genius Next Gen File Integrity Monitoring System

Project Overview
CloudGeniusNextGenFIM is a state-of-the-art File Integrity Monitoring system. It offers enhanced threat detection capabilities and integrates seamlessly with various IT environments. Designed for scalability, real-time monitoring, and cross-platform compatibility, this project marks a significant advancement in the cybersecurity domain.

Features
Real-time Monitoring: Continuous tracking of file changes across various environments.
Scalability and Efficiency: Utilizes batch processing and connection pooling.
Cross-Platform Compatibility: Supports Windows, Linux, and macOS.
Updated Denylist Integration: Utilizes a denylist from Malware Bazaar for effective threat detection.
Robust Error Handling: Advanced mechanisms for error detection and reporting.

Installation
1. Clone the repository:
git clone https://github.com/bturcanu/FIMS.git

2. Install Python 3.x if not already installed.

3. Dependencies
The following Python libraries are required:
os
pyodbc (for database connections)
hashlib
platform
json
tqdm (for progress bars)
concurrent.futures (for parallel processing)
queue
signal
datetime
shutil and stat (in MonitoringMechanism.py)
getpass (in GetConnectionDetails.py)

4. Some dependencies listed are not part of the standard Python library and need to be installed separately. These are:
pyodbc: A Python module that provides access to ODBC databases.
tqdm: A fast, extensible progress bar for loops and CLI.

5. Install the dependencies using pip:
pip install pyodbc tqdm

6. Execute the SQL commands from "DatabaseCreation.sql" on your SQL Server. This will create the necessary database and tables for your FIM system to function correctly.

7. Configuration
Modify directories_config.json to set the directories to be monitored for each platform:

Example Windows configuration:
"Windows": ["C:/Windows", "C:/Program Files", "C:/Test"]

Example Linux configuration:
"Linux": ["/bin", "/etc", "/custom_dir"]

Example macOS configuration:
"Darwin": ["/bin", "/etc", "/usr", "/var", "/custom_dir_mac"]

7. Set up the quarantine directories in directories_config.json for each platform.

8. Updating Denylist
Obtain the latest Full data dump of SHA256 Hashes from Malware Bazaar at https://bazaar.abuse.ch/export/ and name the file "full_sha256".
Place the denylist file in the specified directory in the script.

Execution
Run Initialization.py to set up the initial environment in administrative mode using PowerShell or CMD.
Execute MonitoringMechanism.py to start the monitoring process.
Specify the server name and password when using SQL server authentication, as appropriate. 
