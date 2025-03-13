import os
import json
import string
import secrets
import pyperclip
import subprocess
from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from manager import  check_password, get_password, create_vault 
from libqtile import qtile
from libqtile.widget import base

class PasswordManager(base.ThreadPoolText):
    defaults = [
        ("vault_path", "~/.local/share/password_manager/vault.bin", "Path to the vault"),
    ]
    def __init__(self, **config):
        super().__init__("", **config)
        self.add_defaults(PasswordManager.defaults)
        self.locked = True
        self.vault_path = os.path.expanduser(self.vault_path)
        self.password = ""
        self.add_callbacks(
            {
                "Button1": self.manager,
            })

    def manager(self):
       if not os.path.exists(self.vault_path): 
            cmd = "echo | rofi -dmenu -password -p 'Enter Master Password to make the vault:' -no-config -theme ~/.config/rofi/password-prompt.rasi"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            # Handle not entering anything in the field
            if result.stdout == '':
                subprocess.run(["notify-send", "Password Manager", "Please input a password"])
                self.update(self.poll())
                return
            create_vault(result.stdout.strip())
            subprocess.run(["notify-send", "Password Manager", "Created a new vault"])
            self.update(self.poll())
            return

       cmd = "echo | rofi -dmenu -password -p 'Enter Master Password:' -no-config -theme ~/.config/rofi/password-prompt.rasi"
       result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
       # Handle not entering anything in the field
       if result.stdout == '':
           self.update(self.poll())
           return

       if check_password(result.stdout.strip()):
            self.locked = False
            self.update(self.poll())
            self.password = result.stdout.strip()
            init_cmd = "echo | rofi -dmenu -p '1) Get password for a website\n2) Update password for a website\n3) Add a new password for a website\n4)Delete password for a website: ' -no-config -theme ~/.config/rofi/password-prompt.rasi"
            init_result = subprocess.run(init_cmd, shell=True, capture_output=True, text=True)
            option = int(init_result.stdout.strip())
            # Use a better func name
            data = get_password(self.password, mode='Q')
            if option == 1:
                if len(data["passwords"]) == 0:
                    subprocess.run(["notify-send", "Password Manager", "No entries exist yet, please add a password first"])
                    self.update(self.poll())
                    return
                cmd = "echo | rofi -dmenu -p 'Enter website: ' -no-config -theme ~/.config/rofi/password-prompt.rasi"
                result = subprocess.run(cmd, shell=True, capture_output= True, text=True)
                website = result.stdout.strip()
                if website not in data["passwords"]:
                    subprocess.run(["notify-send", "Password Manager", "Password for given input does not exist in the vault!"])
                    self.locked = True
                    self.update(self.poll())
                    return
                subprocess.run(["notify-send", "Password Manager", "Password copied to clipboard"])
                pyperclip.copy(data["passwords"][website])  
                self.update(self.poll())
                qtile.call_later(5, self.auto_lock)
            elif option == 2:
                if len(data["passwords"]) == 0:
                    subprocess.run(["notify-send", "Password Manager", "No entries exist yet, please add a password first"])
                    self.update(self.poll())
                    return
                self.add_to_vault(mode = 'u')
            elif option == 3:
                self.add_to_vault(mode = 'a')

            else:
                subprocess.run(["notify-send", "Password Manager", "Not Implemented"])
       else:
            subprocess.run(["notify-send", "Password Manager", "❌ Wrong Password"])
            self.locked = True
            self.update(self.poll())

       self.update(self.poll())

    def auto_lock(self):
        self.locked = True
        self.update(self.poll())

    def poll(self) -> str:
        return '🏦'


    def generate_password(self) -> str:
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        return password

    def add_to_vault(self, mode: str) -> None:
        with open(self.vault_path, "rb") as f:
            data = f.read()
        master_hash, encrypted_data = data.split(b"|", 1)
        salt, nonce, tag, cipher_text = encrypted_data[:16], encrypted_data[
            16:28], encrypted_data[28:44], encrypted_data[44:]
        key = hash_secret_raw(secret=self.password.encode(
        ), salt=salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
        vault_data = json.loads(decrypted_data.decode())

        if mode == "a":
            cmd = "echo | rofi -dmenu -p 'Enter website: ' -no-config -theme ~/.config/rofi/password-prompt.rasi"
            result = subprocess.run(cmd, shell=True, capture_output= True, text=True)
            website = result.stdout.strip()
            if website in vault_data["passwords"]:
                subprocess.run(["notify-send", "Password Manager", "Website data already exists in the vault"])
                self.update(self.poll())
                return
            password = self.generate_password()
            subprocess.run(["notify-send", "Password Manager", "Password generated, stored and copied to clipboard"])
            vault_data["passwords"][website] = password
            vault_data = json.dumps(vault_data).encode("utf-8")
            pyperclip.copy(password)
        elif mode == "u":
            cmd = "echo | rofi -dmenu -p 'Enter website: ' -no-config -theme ~/.config/rofi/password-prompt.rasi"
            result = subprocess.run(cmd, shell=True, capture_output= True, text=True)
            website = result.stdout.strip()
            if website not in vault_data["passwords"]:
                subprocess.run(["notify-send", "Password Manager", "Website data does not exist in the vault"])
                self.update(self.poll())
                return
            password = self.generate_password()
            subprocess.run(["notify-send", "Password Manager", "Password updated and copied to clipboard"])
            vault_data["passwords"][website] = password
            vault_data = json.dumps(vault_data).encode("utf-8")
            pyperclip.copy(password)

        new_nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=new_nonce)
        cipher_text, tag = cipher.encrypt_and_digest(vault_data)
        data = master_hash + b"|" + salt + new_nonce + tag + cipher_text
        with open(self.vault_path, "wb") as f:
            f.seek(0)
            f.write(data)

        return

