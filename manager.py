import os
import sys
import json
import string
import secrets
import getpass
import pyperclip
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type
from argon2 import PasswordHasher

VAULT_PATH = os.path.expanduser("~/.local/share/password_manager/vault.bin")

# NOTES:
# AES-GCM --> 12 byte nonce

# IMP: 
# Make sure create_vault is only called when the vault.bin file DOES NOT EXIST.
def create_vault(master_password: str) -> None:
    ph = PasswordHasher()
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)
    key = hash_secret_raw(secret=master_password.encode(
    ), salt=salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)
    vault_data = json.dumps({"passwords": {}}).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_text, tag = cipher.encrypt_and_digest(vault_data)
    master_hash = ph.hash(master_password).encode("utf-8")
    data = master_hash + b"|" + salt + nonce + tag + cipher_text
    with open(VAULT_PATH, "wb") as f:
        f.write(data)

# Checks whether the password matches the master password
def check_password(password: str) -> bool:
    with open(VAULT_PATH, "rb") as f:
        data = f.read()

    ph = PasswordHasher()
    master_hash = data.split(b"|", 1)[0]
    try:
        ph.verify(master_hash.decode(), password)
        return True
    except:
        return False


def open_vault(master_password: str) -> dict[str, dict[str, str]]:
    ph = PasswordHasher()
    with open(VAULT_PATH, "rb") as f:
        data = f.read()
    master_hash, encrypted_data = data.split(b"|", 1)

    try:
        ph.verify(master_hash, master_password)
    except:
        print("Incorrect master password")
        sys.exit()

    salt, nonce, tag, cipher_text = encrypted_data[:16], encrypted_data[
        16:28], encrypted_data[28:44], encrypted_data[44:]
    key = hash_secret_raw(secret=master_password.encode(
    ), salt=salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
    except:
        print("Something unexpected happened")
        sys.exit()

    vault_data = json.loads(decrypted_data.decode())
    return vault_data


# Added mode to specify whether to [a]dd or [u]pdate
def add_to_vault(master_password: str, mode: str) -> None:
    ph = PasswordHasher()
    with open(VAULT_PATH, "rb") as f:
        data = f.read()
    master_hash, encrypted_data = data.split(b"|", 1)

    try:
        ph.verify(master_hash, master_password)
    except:
        print("Incorrect master password")
        sys.exit()

    salt, nonce, tag, cipher_text = encrypted_data[:16], encrypted_data[
        16:28], encrypted_data[28:44], encrypted_data[44:]
    key = hash_secret_raw(secret=master_password.encode(
    ), salt=salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
    except:
        print("Something unexpected happened")
        sys.exit()

    vault_data = json.loads(decrypted_data.decode())

    if mode == "a":
        website = input("Enter website: ")
        if website in vault_data["passwords"]:
            print("Website already exists")
            print("Password is ", vault_data["passwords"][website])
            sys.exit()
        password = generate_password()
        print("Generated password for this website: ", password)
        print("Storing the password....")
        vault_data["passwords"][website] = password
        vault_data = json.dumps(vault_data).encode("utf-8")
    elif mode == "u":
        website = input("Enter website to update: ")
        if website not in vault_data["passwords"]:
            print("Website does not exist")
            sys.exit()
        password = generate_password()
        print("New generated password for this website: ", password)
        print("Storing the password....")
        vault_data["passwords"][website] = password
        vault_data = json.dumps(vault_data).encode("utf-8")

    new_nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=new_nonce)
    cipher_text, tag = cipher.encrypt_and_digest(vault_data)
    data = master_hash + b"|" + salt + new_nonce + tag + cipher_text
    with open(VAULT_PATH, "wb") as f:
        f.seek(0)
        f.write(data)


def delete_from_vault(master_password: str) -> None:
    with open(VAULT_PATH, "rb") as f:
        data = f.read()
    website = input("Enter website password to delete: ")
    master_hash, encrypted_data = data.split(b"|", 1)
    salt, nonce, tag, cipher_text = encrypted_data[:16], encrypted_data[
        16:28], encrypted_data[28:44], encrypted_data[44:]
    key = hash_secret_raw(secret=master_password.encode(),
                            salt=salt, time_cost=4, memory_cost=65536,
                          parallelism=2, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    vault_data = cipher.decrypt_and_verify(cipher_text, tag)
    passwords = json.loads(vault_data.decode())
    del passwords["passwords"][website]
    vault_data = json.dumps(passwords).encode("utf-8")
    new_nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=new_nonce)
    cipher_text, tag = cipher.encrypt_and_digest(vault_data)
    data = master_hash + b"|" + salt + new_nonce + tag + cipher_text
    with open(VAULT_PATH, "wb") as f:
        f.seek(0)
        f.write(data)

def get_password(master_password: str, mode: str = 'T') -> dict[str, dict[str, str]] | None:
    with open(VAULT_PATH, "rb") as f:
        data = f.read()

    encrypted_data = data.split(b"|", 1)[1]
    salt, nonce, tag, cipher_text = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:44], encrypted_data[44:]
    key = hash_secret_raw(secret=master_password.encode(),
                            salt=salt, time_cost=4, memory_cost=65536,
                          parallelism=2, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
    except:
        print("Something weird happened")
        sys.exit()

    vault_data = json.loads(decrypted_data.decode())
    if mode == 'Q':
        return vault_data

    website = input("Enter website to retrieve password: ")
    if website in vault_data["passwords"]:
        pyperclip.copy(vault_data["passwords"][website])
        print("Password copied to clipboard")
    else:
        print("Website does not exist in the vault")
        sys.exit()
    return {}


def generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for _ in range(16))
    return password


# Terminal based manager
if __name__ == "__main__":
    if not os.path.exists(VAULT_PATH):
        master_password = getpass.getpass(
            "Enter master password to create the vault: ")
        create_vault(master_password)
        sys.exit()

    master_password = getpass.getpass("Enter master password: ")
    print(check_password(master_password))

    try:
        vault_data = open_vault(master_password)
    except:
        sys.exit()


    while (True):
        print("-------------------------------")
        print("1. View passwords stored in vault")
        print("2. Get password for a website")
        print("3. Add to vault")
        print("4. Change existing password")
        print("5. Delete from vault")
        print("9. Exit")
        option = int(input("Enter option: "))

        match option:
            case 1:
                vault_data = open_vault(master_password)
                print(type(vault_data))
                print("-------------------------------")
                for key in vault_data["passwords"]:
                    print(key)
                print("-------------------------------")
                print(vault_data)
                continue
            case 2:
                get_password(master_password)
                continue
            case 3:
                add_to_vault(master_password, "a")
                continue
            case 4:
                add_to_vault(master_password, "u")
                continue
            case 5:
                delete_from_vault(master_password)
                continue
            case 9:
                sys.exit()
