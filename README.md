# Proton-To-KeePass (Enhanced Fork)

Convert your **Proton Pass** vault into a secure, offline **KeePass KDBX** file – with full field support, TOTP handling, and intelligent mapping.

> This is a heavily modified fork of the original project [cadomac/Proton-To-KeePass](https://github.com/cadomac/Proton-To-KeePass). It fixes major bugs, improves compatibility, and ensures **ALL data** from Proton Pass exports is safely migrated into KeePass.

---

## 🚀 Features

✅ Converts Proton Pass `.pgp` export to KeePass `.kdbx`  
✅ Fully preserves **usernames**, including fallback to `"email"`, `"login"`, `"Email (aliases)"`  
✅ Preserves all **custom fields** like `"IP Address"`, `"alias email"`, etc., into KeePass custom properties  
✅ Converts and extracts **TOTP/2FA secrets** from `otpauth://` URIs  
✅ Automatically handles **duplicate entries** with safe timestamps  
✅ Saves original **creation & modification timestamps**  
✅ Merges or separates vaults into folders  
✅ Optionally separates TOTP entries into a dedicated KeePass file  
✅ Supports PGP via GnuPG CLI  
✅ Outputs sanitized, XML-compatible values (no more `NULL byte` or XPath crashes)  
✅ Saves a debug version of the decrypted vault to assist with troubleshooting

---

## 📦 Installation

### 🔧 Requirements

- Python 3.8+
- GnuPG (CLI)
- KeePass-compatible software (e.g. KeePassXC)
- `pip install -r requirements.txt`

### Install dependencies:
```bash
pip install -r requirements.txt
