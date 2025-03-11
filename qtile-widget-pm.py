import os
import pyperclip
import subprocess
from manager import check_password, get_password, create_vault
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
        self.vault_path = os.path.expanduser("~/.local/share/password_manager/vault.bin")
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
            cmd = "echo | rofi -dmenu -p '' -no-config -theme ~/.config/rofi/password-prompt.rasi"
            result = subprocess.run(cmd, shell=True, capture_output= True, text=True)
            website = result.stdout.strip()
            data = get_password(self.password, mode='Q')
            if website not in data["passwords"]:
                subprocess.run(["notify-send", "Password Manager", "Password for given input does not exist in the vault!"])
                self.locked = True
                self.update(self.poll())
            else:
                subprocess.run(["notify-send", "Password Manager", "Password copied to clipboard"])
                pyperclip.copy(data["passwords"][website])  
                self.update(self.poll())
                qtile.call_later(5, self.auto_lock)
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
