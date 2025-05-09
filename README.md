# 🛡️ **Chrome Credential Extractor via App Bound Key Decryption**

---

> ⚠️ **DISCLAIMER — READ THIS FIRST**
>
> This project is provided **strictly for educational, forensic, and authorized security testing purposes only**.
> 
> ❗ **Any unauthorized use of this script to access, extract, or manipulate user credentials is illegal** and may violate data privacy laws, including the **Computer Fraud and Abuse Act (CFAA)**, **GDPR**, and others.
>
> **The author is not responsible for any misuse, damage, loss, or legal consequences** that may arise from using this tool.
>
> You are solely responsible for ensuring you have proper authorization before executing this script on any system.

---

This script extracts and decrypts **Google Chrome's cookies** and **saved login credentials** by reverse-engineering Chrome's **App Bound Encryption** mechanism and Windows **DPAPI**.

It uses **local SYSTEM-level decryption** (via **PsExec**) to unwrap Chrome's encrypted master key, then decrypts stored **v20-format credentials** using **AES-GCM** or **ChaCha20-Poly1305**.

---

## 🚀 **New Working Method (Post-Patch, Chrome 136+)**

As of **Chrome Version `136.0.7103.93 (64-bit)`**, all stored credentials and cookies use **v20 format** with **AEAD (GCM/ChaCha20)** encryption, tied to both the OS and user profile.

✅ This script:
- Decrypts the **App Bound key** using **SYSTEM** and **user DPAPI**
- Supports both **AES-GCM** and **ChaCha20-Poly1305 AEAD** unwrapping
- Works flawlessly with Chrome's updated security model (**v136+**)

---

## ⚙️ **Features**

✅ Supports latest **Chrome version (`136.0.7103.93`)**  
✅ Decrypts **Chrome’s App Bound Encryption Key**  
✅ Leverages **Windows DPAPI** (**User** + **SYSTEM** contexts)  
✅ Decrypts both **v20-format** cookies and passwords  
✅ Uses **pypsexec** to spawn **SYSTEM-level** code  
✅ Handles both **AES-GCM** and **ChaCha20-Poly1305**  
✅ Includes cleanup retries for **PsExec** service removal

---

## 📜 **Script Versions**

There are two versions of the script available:

- **`decrypt.py`**: A simple version that decrypts and displays passwords and cookies.
- **`Chrome-Decrypt.py`**: An improved version with additional features (recommended).  
  Run `python Chrome-Decrypt.py --help` to see available options:

  ```
  usage: Chrome-Decrypt.py [-h] [-o {console,json,csv}] [-f FILE] [--no-cookies] [--no-passwords] [-v]

  **Chrome Password and Cookie Extractor**

  options:
    -h, --help            show this help message and exit
    -o {console,json,csv}, --output {console,json,csv}
                          Output format (default: console)
    -f FILE, --file FILE  Output file name (default: chrome_data_YYYY-MM-DD.ext)
    --no-cookies          Skip cookie extraction
    --no-passwords        Skip password extraction
    -v, --verbose         Enable verbose output
  ```

---

## ✅ **CLI Tool Benefits**

- Output to **console**, **JSON**, or **CSV**
- Skip **cookies** or **passwords** selectively
- Supports **logging**, **verbose/debug** mode
- Easier automation in **forensics** & **IR tools**

---

## 📦 **Installation**

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/chrome-decryptor.git
   cd chrome-decryptor
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔐 **Requirements**

- 🧑‍💻 **Administrator privileges** (script auto-elevates if needed)
- 🪟 **Windows 10** or **11 (64-bit)**
- 🌐 **Google Chrome v136.0.7103.93** or later
- 🐍 **Python 3.8+**

### 📍 **Data Locations**
- Pulls data from:
  - **`Cookies`**: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
  - **`Login Data`**: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`

---

## 📜 **requirements.txt**

```
pycryptodome
pypsexec
pywin32
```

---

## 🧪 **Usage**

**Basic Script:**
```bash
python decrypt.py
```

**Recommended CLI Tool:**
```bash
python Chrome-Decrypt.py -o json -f chrome_data.json
```

---

## 📁 **File Structure**

```
chrome-decryptor/
├── decrypt.py             ← **Base script**
├── Chrome-Decrypt.py      ← **CLI version**
├── requirements.txt       ← **Python dependencies**
├── README.md              ← **This file**
├── LICENSE                ← **Legal license (MIT, etc.)**
└── .gitignore             ← **Optional for venvs/pycache**
```

---

## 🧼 **PsExec Cleanup**

- Script automatically removes **PsExec services** after use
- Retries cleanup on failure (e.g., **STATUS_CANNOT_DELETE**)
- If services persist, manual removal may be required

---

## 📄 **License**

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## ⚠️ **Final Reminder**

❗ This tool is intended strictly for:

- **Digital forensics & incident response (DFIR)**
- **Penetration testing** (with written authorization)
- **Red team operations** (with consent)

❌ **Do NOT use this tool on systems you do not own or explicitly have permission to test.**
