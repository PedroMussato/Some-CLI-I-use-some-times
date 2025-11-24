# 🔐 PyCript 1.0.0 - File Encryption/Decryption Script

## 📌 What it does
- Encrypts files with a user-provided password.  
- Decrypts previously encrypted files using the same password.  
- Password entry is secure: it is hidden while typing in the terminal.

---

## ⚙️ How it works
- Uses the **cryptography (Fernet/AES)** library for encryption and decryption.  
- Derives a secure key from the password using **PBKDF2 with SHA256**.  
- Original file → encrypted file (`.enc`).  
- Encrypted file → decrypted file (`.dec`).  

---

## 🚀 How to use

### Encrypt a file
```bash
python3 main.py -i file.txt -e
```
➡️ Generates `file.txt.enc`

### Decrypt a file
```bash
python3 main.py -i file.txt.enc -d
```
➡️ Generates `file.txt.dec`

During both operations, the program will prompt you for a password securely (input hidden).

---

## 🛠️ Command-line arguments

| Argument | Description |
|----------|-------------|
| `-i, --input-file` | Input file (required) |
| `-e, --encrypt`    | Encrypt the file |
| `-d, --decrypt`    | Decrypt the file |

---

## ⚠️ Notes
- If the wrong password is entered during decryption, the script will show an error.  
- Decrypted files are saved with `.dec` extension to avoid overwriting the original.  

