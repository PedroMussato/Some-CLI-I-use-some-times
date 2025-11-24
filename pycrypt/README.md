# Secure Tar Encryptor

A Python CLI tool to **archive files/directories into tar**, compress them with the **best native compression (xz)**, and **encrypt/decrypt** using a password-derived key.  
This makes it easy to securely back up and restore entire folders or single files.

---

## ✨ Features

- **Password-based encryption** using PBKDF2 + Fernet (AES-128 under the hood).  
- **Tar archiving**: supports both single files and directories (including nested subdirectories).  
- **Best compression**: uses `xz` (LZMA) for optimal compression ratio.  
- **Custom output filename**: specify the name of the tar or decrypted tar file.  
- **Secure password prompt**: hides input when typing.  
- **Modular design**: functions can be reused in other scripts.

---

## 📦 Requirements

- Python 3.7+
- `cryptography` library

Install dependencies:

```bash
pip install cryptography
```

---

## 🚀 Usage

### Encrypt a directory

```bash
python secure_tar.py -i my_folder -e
```

Output: `data.tar.xz.enc`

---

### Encrypt with a custom name

```bash
python secure_tar.py -i my_folder -e -o mybackup.tar.xz
```

Output: `mybackup.tar.xz.enc`

---

### Decrypt and extract

```bash
python secure_tar.py -i data.tar.xz.enc -d -t output_folder
```

Extracts contents into `output_folder`.

---

### Decrypt with a custom tar name

```bash
python secure_tar.py -i mybackup.tar.xz.enc -d -o restored.tar.xz -t output_folder
```

Creates `restored.tar.xz` and extracts into `output_folder`.

---

## 🔧 Command-line Options

| Option | Description |
|--------|-------------|
| **`-i, --input`** | Input file/directory (for encrypt) or encrypted tar (for decrypt) |
| **`-e, --encrypt`** | Encrypt input into `.tar.xz.enc` |
| **`-d, --decrypt`** | Decrypt `.tar.xz.enc` and extract |
| **`-o, --output`** | Custom output filename (tar or decrypted tar) |
| **`-t, --target`** | Target directory for extraction (default: current directory) |

---

## 🔒 Security Notes

- The key is derived from your password using **PBKDF2-HMAC-SHA256** with 100,000 iterations.  
- Encryption uses **Fernet**, which provides AES encryption with authentication.  
- Always use strong, unique passwords for maximum security.
