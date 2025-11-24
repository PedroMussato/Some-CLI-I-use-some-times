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

# Função para gerar chave a partir da palavra-passe
def gerar_chave(password: str, salt: bytes = b'saltpadrao'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Função para encriptar arquivo
def encriptar(arquivo: str, password: str):
    chave = gerar_chave(password)
    fernet = Fernet(chave)

    with open(arquivo, "rb") as f:
        dados = f.read()

    dados_encriptados = fernet.encrypt(dados)

    novo_arquivo = arquivo + ".enc"
    with open(novo_arquivo, "wb") as f:
        f.write(dados_encriptados)

    print(f"✅ Arquivo encriptado gerado: {novo_arquivo}")

# Função para decriptar arquivo
def decriptar(arquivo: str, password: str):
    chave = gerar_chave(password)
    fernet = Fernet(chave)

    with open(arquivo, "rb") as f:
        dados_encriptados = f.read()

    try:
        dados = fernet.decrypt(dados_encriptados)
    except Exception:
        print("❌ Senha incorreta ou arquivo inválido!")
        return

    novo_arquivo = arquivo.replace(".enc", ".dec")
    with open(novo_arquivo, "wb") as f:
        f.write(dados)

    print(f"✅ Arquivo decriptado gerado: {novo_arquivo}")

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encriptar ou decriptar arquivos com senha")
    parser.add_argument("-i", "--input-file", required=True, help="Arquivo de entrada")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encriptar arquivo")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decriptar arquivo")

    args = parser.parse_args()

    # Solicita senha de forma segura
    password = getpass("Digite a senha: ")

    if args.encrypt:
        encriptar(args.input_file, password)
    elif args.decrypt:
        decriptar(args.input_file, password)
    else:
        print("Escolha --encrypt ou --decrypt")
