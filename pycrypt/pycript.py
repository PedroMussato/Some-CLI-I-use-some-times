"""
===========================================
 Script Name : PyCrypt
 Description : File Encrypt/Decrypt Tool
 Creator     : Pedro Mussato
 Version     : 1.2.0
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


def generate_key(password: str, salt: bytes = b'default_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def create_tar(path: str, tar_name: str = "archive.tar.xz", compression: str = "w:xz"):
    """Create a tar archive with best native compression (xz)."""
    with tarfile.open(tar_name, compression) as tar:
        tar.add(path, arcname=os.path.basename(path))
    return tar_name

def extract_tar(tar_file: str, destination: str = "."):
    """Extract a tar archive into the destination directory."""
    with tarfile.open(tar_file, "r:*") as tar:  # r:* auto-detects compression
        tar.extractall(path=destination)


def encrypt_tar(path: str, password: str, output_name: str = None):
    """Create a compressed tar from path and encrypt it."""
    tar_name = output_name if output_name else "data.tar.xz"
    tar_name = create_tar(path, tar_name, "w:xz")  # best compression
    key = generate_key(password)
    fernet = Fernet(key)

    with open(tar_name, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    enc_file = tar_name + ".enc"

    with open(enc_file, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ Encrypted tar created: {enc_file}")


def decrypt_tar(enc_file: str, password: str, destination: str = ".", output_name: str = None):
    """Decrypt an encrypted tar and extract it."""
    key = generate_key(password)
    fernet = Fernet(key)

    with open(enc_file, "rb") as f:
        encrypted_data = f.read()

    try:
        data = fernet.decrypt(encrypted_data)
    except Exception:
        print("❌ Wrong password or invalid file!")
        return

    tar_file = output_name if output_name else enc_file.replace(".enc", ".dec.tar.xz")
    with open(tar_file, "wb") as f:
        f.write(data)

    extract_tar(tar_file, destination)
    print(f"✅ Decrypted and extracted to: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt or decrypt tar archives with a password")
    parser.add_argument("-i", "--input", required=True, help="Input file or directory (for encrypt) or encrypted tar (for decrypt)")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt file/directory into tar.xz.enc")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt tar.xz.enc and extract")
    parser.add_argument("-o", "--output", help="Custom output filename (for tar or decrypted tar)")
    parser.add_argument("-t", "--target", default=".", help="Target directory for extraction")

    args = parser.parse_args()
    password = getpass("Enter password: ")

    if args.encrypt:
        encrypt_tar(args.input, password, args.output)
    elif args.decrypt:
        decrypt_tar(args.input, password, args.target, args.output)
    else:
        print("Choose --encrypt or --decrypt")
