import getpass



def get_connection_details():
    # Ask the user for authentication method
    while True:
        auth_method = input("Which authentication method would you like to use? (Enter 'windows' for Windows Authentication or 'sql' for SQL Server Authentication): ").strip().lower()
        if auth_method in ['windows', 'sql']:
            break
        else:
            print("Invalid authentication method. Please choose 'windows' or 'sql'.")
    
    # Validate and get the server name
    while True:
        DB_SERVER = input("Enter the server name: ").strip()
        if DB_SERVER:
            break
        else:
            print("Server name cannot be empty. Please enter a valid server name.")
    
    # Database name
    while True:
        DB_DATABASE = input("Enter the database name (default is 'FileIntegrityDB'): ").strip()
        if not DB_DATABASE:
            DB_DATABASE = 'FileIntegrityDB'
            break
        elif len(DB_DATABASE) > 3:  # Simple validation for database name length
            break
        else:
            print("Database name seems too short. Please enter a valid database name.")
    
    # Get username and password based on authentication method
    DB_USERNAME = None
    DB_PASSWORD = None
    if auth_method == 'sql':
        while True:
            DB_USERNAME = input("Enter the username: ").strip()
            if DB_USERNAME:
                break
            else:
                print("Username cannot be empty. Please enter a valid username.")
        
        DB_PASSWORD = getpass.getpass("Enter the password: ").strip()
    
    return {
        'auth_method': auth_method,
        'DB_SERVER': DB_SERVER,
        'DB_DATABASE': DB_DATABASE,
        'DB_USERNAME': DB_USERNAME,
        'DB_PASSWORD': DB_PASSWORD
    }