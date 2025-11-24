"""
===========================================
 Script Name : PyCrypt
 Description : File Encrypt/Decrypt Tool
 Creator     : Pedro Mussato
 Version     : 1.0.0
 Date        : 24/11/2025
===========================================
"""
import argparse
import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Function to generate a key from the password
def generate_key(password: str, salt: bytes = b'default_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt a file
def encrypt(file: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    new_file = file + ".enc"
    with open(new_file, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ Encrypted file created: {new_file}")

# Function to decrypt a file
def decrypt(file: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file, "rb") as f:
        encrypted_data = f.read()

    try:
        data = fernet.decrypt(encrypted_data)
    except Exception:
        print("❌ Wrong password or invalid file!")
        return

    new_file = file.replace(".enc", ".dec")
    with open(new_file, "wb") as f:
        f.write(data)

    print(f"✅ Decrypted file created: {new_file}")

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files with a password")
    parser.add_argument("-i", "--input-file", required=True, help="Input file")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt file")

    args = parser.parse_args()

    # Secure password prompt
    password = getpass("Enter password: ")

    if args.encrypt:
        encrypt(args.input_file, password)
    elif args.decrypt:
        decrypt(args.input_file, password)
    else:
        print("Choose --encrypt or --decrypt")
