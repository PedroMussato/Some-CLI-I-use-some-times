"""
===========================================
 Script Name : PyCrypt
 Description : File Encrypt/Decrypt Tool
 Creator     : Pedro Mussato
 Version     : 1.1.0
 Date        : 24/11/2025
===========================================
"""

import argparse
import os
import base64
import tarfile
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def generate_key(password: str, salt: bytes = b"default_salt"):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def create_tar(path: str, tar_name: str = "archive.tar.gz"):
    """Create a tar.gz archive from a file or directory."""
    with tarfile.open(tar_name, "w:gz") as tar:
        tar.add(path, arcname=os.path.basename(path))
    return tar_name


def extract_tar(tar_file: str, destination: str = "."):
    """Extract a tar.gz archive into the destination directory."""
    with tarfile.open(tar_file, "r:gz") as tar:
        tar.extractall(path=destination)


def encrypt_tar(path: str, password: str):
    """Create a tar.gz from path and encrypt it."""
    tar_name = create_tar(path, "data.tar.gz")
    key = generate_key(password)
    fernet = Fernet(key)

    with open(tar_name, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    enc_file = tar_name + ".enc"

    with open(enc_file, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ Encrypted tar created: {enc_file}")


def decrypt_tar(enc_file: str, password: str, destination: str = "."):
    """Decrypt an encrypted tar.gz and extract it."""
    key = generate_key(password)
    fernet = Fernet(key)

    with open(enc_file, "rb") as f:
        encrypted_data = f.read()

    try:
        data = fernet.decrypt(encrypted_data)
    except Exception:
        print("❌ Wrong password or invalid file!")
        return

    tar_file = enc_file.replace(".enc", ".dec.tar.gz")
    with open(tar_file, "wb") as f:
        f.write(data)

    extract_tar(tar_file, destination)
    print(f"✅ Decrypted and extracted to: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt tar archives with a password"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file or directory (for encrypt) or encrypted tar (for decrypt)",
    )
    parser.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="Encrypt file/directory into tar.gz.enc",
    )
    parser.add_argument(
        "-d", "--decrypt", action="store_true", help="Decrypt tar.gz.enc and extract"
    )
    parser.add_argument(
        "-o", "--output", default=".", help="Output directory for extraction"
    )

    args = parser.parse_args()

    password = getpass("Enter password: ")

    if args.encrypt:
        encrypt_tar(args.input, password)
    elif args.decrypt:
        decrypt_tar(args.input, password, args.output)
    else:
        print("Choose --encrypt or --decrypt")
