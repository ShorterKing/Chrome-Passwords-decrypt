# 🛡️ Chrome Credential Extractor via App Bound Key Decryption

This script extracts and decrypts **Google Chrome's cookies and saved login credentials** by reverse-engineering Chrome's **App Bound Encryption** mechanism and Windows **DPAPI**.

It uses **local SYSTEM-level decryption** (via PsExec) to unwrap Chrome's encrypted master key, then decrypts stored v20-format credentials using AES-GCM or ChaCha20-Poly1305.

---

## 🚀 New Working Method (Post-Patch, Chrome 136+)

⚠️ Google Chrome v80+ introduced App Bound Encryption and later versions further strengthened it. As of **Chrome Version `136.0.7103.93 (64-bit)`**, all stored credentials and cookies use **v20 format** with AEAD (GCM/ChaCha20) encryption, tied to both the OS and user profile.

✅ This script implements a **fully working bypass** for Chrome 136+ by:
- Decrypting the App Bound key using both SYSTEM and user DPAPI
- Supporting both AES-GCM and ChaCha20-Poly1305 AEAD unwrapping
- Providing v20 cookie/password decryption with no user interaction required

---

## ⚙️ Features

✅ Supports latest Chrome version (`136.0.7103.93`)  
✅ Decrypts Chrome’s App Bound Encryption Key  
✅ Leverages Windows DPAPI (User + SYSTEM contexts)  
✅ Decrypts both `v20`-format cookies and passwords  
✅ Uses `pypsexec` to spawn SYSTEM-level code  
✅ Handles both AES-GCM and ChaCha20-Poly1305 key unwrapping  
✅ Includes cleanup retries for stubborn PsExec services

---

## ⚠️ Requirements & Notes

### 🔐 Privileges
- **Must be run as Administrator**
  - If not, the script automatically relaunches itself elevated via `ShellExecuteW(runas)`

### 💻 Operating System
- Windows 10 / 11
- SYSTEM-level process execution must be supported

### 🌐 Browser
- **Google Chrome v136.0.7103.93 (Official Build)** — Fully Supported  
- Extracts data from:
  - `Cookies`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
  - `Login Data`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`

### 📦 Python
- Version: **Python 3.8+**

---

## 📦 Dependencies

Install all required packages using:

```bash
pip install -r requirements.txt
