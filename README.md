# 🛡️ Chrome Credential Extractor via App Bound Key Decryption

---

> ⚠️ **DISCLAIMER — READ THIS FIRST**
>
> This project is provided **strictly for educational, forensic, and authorized security testing purposes only**.
> 
> ❗ **Any unauthorized use of this script to access, extract, or manipulate user credentials is illegal** and may violate data privacy laws, including the Computer Fraud and Abuse Act (CFAA), GDPR, and others.
>
> **The author is not responsible for any misuse, damage, loss, or legal consequences** that may arise from using this tool.
>
> You are solely responsible for ensuring you have proper authorization before executing this script on any system.

---

This script extracts and decrypts **Google Chrome's cookies and saved login credentials** by reverse-engineering Chrome's **App Bound Encryption** mechanism and Windows **DPAPI**.

It uses **local SYSTEM-level decryption** (via PsExec) to unwrap Chrome's encrypted master key, then decrypts stored v20-format credentials using AES-GCM or ChaCha20-Poly1305.

---

## 🚀 New Working Method (Post-Patch, Chrome 136+)

As of **Chrome Version `136.0.7103.93 (64-bit)`**, all stored credentials and cookies use **v20 format** with AEAD (GCM/ChaCha20) encryption, tied to both the OS and user profile.

✅ This script:
- Decrypts the App Bound key using SYSTEM and user DPAPI
- Supports both AES-GCM and ChaCha20-Poly1305 AEAD unwrapping
- Works flawlessly with Chrome's updated security model (v136+)

---

## ⚙️ Features

✅ Supports latest Chrome version (`136.0.7103.93`)  
✅ Decrypts Chrome’s App Bound Encryption Key  
✅ Leverages Windows DPAPI (User + SYSTEM contexts)  
✅ Decrypts both `v20`-format cookies and passwords  
✅ Uses `pypsexec` to spawn SYSTEM-level code  
✅ Handles both AES-GCM and ChaCha20-Poly1305  
✅ Includes cleanup retries for PsExec service removal

---

## ⚠️ Requirements & Notes

### 🔐 Privileges
- **Must be run as Administrator**
  - If not, the script automatically relaunches itself elevated via `ShellExecuteW(runas)`

### 💻 Operating System
- Windows 10 / 11

### 🌐 Browser
- **Google Chrome v136.0.7103.93 (Official Build)**  
- Pulls data from:
  - `Cookies`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
  - `Login Data`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`

### 📦 Python
- Version: **Python 3.8+**

---

## 📦 Dependencies

Install with:

```bash
pip install -r requirements.txt
