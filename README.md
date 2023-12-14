# Cloud Genius Next Gen File Integrity Monitoring System

## Project Overview
CloudGeniusNextGenFIM is a state-of-the-art File Integrity Monitoring system. It offers enhanced threat detection capabilities and integrates seamlessly with various IT environments. Designed for scalability, real-time monitoring, and cross-platform compatibility, this project marks a significant advancement in the cybersecurity domain. Video presentation at https://drive.google.com/file/d/14PvD82-N1X5zU4SoWkTflnAR8wz7OlYx/view?usp=sharing.

## Features
1. Real-time Monitoring: Continuous tracking of file changes across various environments.
2. Scalability and Efficiency: Utilizes batch processing and connection pooling.
3. Cross-Platform Compatibility: Supports Windows, Linux, and macOS.
4. Updated Denylist Integration: Utilizes a denylist from Malware Bazaar for effective threat detection.
5. Robust Error Handling: Advanced mechanisms for error detection and reporting.

## Installation
1. Clone the repository:
`git clone https://github.com/bturcanu/FIMS.git`

2. Install Python 3.x if not already installed.

3. Dependencies: The following Python libraries are required:  
`os`  
`pyodbc` (for database connections)  
`hashlib`  
`platform`  
`json`  
`tqdm` (for progress bars)  
`concurrent.futures` (for parallel processing)  
`queue`  
`signal`  
`datetime`  
`shutil` and `stat` (in MonitoringMechanism.py)  
`getpass` (in GetConnectionDetails.py)  

4. Some dependencies listed are not part of the standard Python library and need to be installed separately. These are:  
`pyodbc`: A Python module that provides access to ODBC databases.  
`tqdm`: A fast, extensible progress bar for loops and CLI.  

5. Install the dependencies using pip:  
`pip install pyodbc tqdm`

6. Execute the SQL commands from "DatabaseCreation.sql" on your SQL Server. This will create the necessary database and tables for your FIM system to function correctly.

7. Configuration  
Modify directories_config.json to set the directories to be monitored for each platform:

  Example Windows configuration:  
  `"Windows": ["C:/Windows", "C:/Program Files", "C:/Test"]`

  Example Linux configuration:  
  `"Linux": ["/bin", "/etc", "/custom_dir"]`

  Example macOS configuration:  
  `"Darwin": ["/bin", "/etc", "/usr", "/var", "/custom_dir_mac"]`

8. Set up the quarantine directories in directories_config.json for each platform.

9. Updating Denylist
Obtain the latest Full data dump of SHA256 Hashes from Malware Bazaar at https://bazaar.abuse.ch/export/ and name the file `full_sha256`. Place the denylist file in the specified directory in the script.

## Execution
1. Run `Initialization.py` to set up the initial environment in administrative mode using PowerShell or CMD.
2. Execute `MonitoringMechanism.py` to start the monitoring process.
3. Specify the server name and password when using SQL server authentication, as appropriate.
4. Review the log details in the newly created `monitoring_log`.
