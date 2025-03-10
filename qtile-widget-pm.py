import pyperclip
import subprocess
from manager import check_password, get_password 
from libqtile import qtile
from libqtile.widget import base

class PasswordManager(base.ThreadPoolText):
    defaults = [
        ("vault_path", "~/.local/share/password_manager/vault.bin", "Path to the vault"),
        ("default_text",'', 'Default text that is displayed'),
    ]
    def __init__(self, **config):
        super().__init__("", **config)
        self.add_defaults(PasswordManager.defaults)
        self.locked = True
        self.password = ""
        self.add_callbacks(
            {
                "Button1": self.manager,
            })

    def manager(self):
        cmd = "echo | rofi -dmenu -password -p 'Enter Master Password:' -no-config -theme ~/.config/rofi/password-prompt.rasi"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

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
        print("THIS IS IN THE FUNCTION")
        self.locked = True
        self.update(self.poll())

    def poll(self) -> str:
        return '🏦'
