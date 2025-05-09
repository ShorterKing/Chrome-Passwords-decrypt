# 🛡️ Chrome Credential Extractor via App Bound Key Decryption

This script extracts and decrypts **Google Chrome's cookies and saved login credentials** by reverse-engineering Chrome's **App Bound Encryption** mechanism and Windows **DPAPI**.

It uses **local SYSTEM-level decryption** (via PsExec) to unwrap Chrome's encrypted master key, then decrypts stored v20-format credentials using AES-GCM or ChaCha20-Poly1305.

---

## ⚙️ Features

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
  - If not, the script attempts to relaunch itself with elevated rights via `ShellExecuteW(runas)`.

### 💻 Operating System
- Windows 10 / 11
- Windows must support **DPAPI** and allow **SYSTEM-level service execution**

### 🌐 Browser
- Google Chrome installed
- Extracts from:
  - `Cookies`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
  - `Login Data`: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`

### 📦 Python
- Version: **Python 3.8+**

---

## 📦 Dependencies

Install with:

```bash
pip install -r requirements.txt
