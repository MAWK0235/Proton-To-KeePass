import gnupg
import json
import re
import sys
from datetime import datetime
from proton_to_keepass.entry import Entry
from proton_to_keepass.config import Config

class Converter():
  def __init__ (self, config: Config):
    self.gpg = gnupg.GPG(config.gnupg_path)
    self.filepath = config.encrypted_file_path
    self.passphrase = config.encrypted_file_passkey
    self.decrypted_file = None
    self.vaults = None
  def decrypt_file_to_json(self):
    decrypted = self.gpg.decrypt_file(self.filepath, passphrase=self.passphrase)
    if decrypted.status == "bad passphrase" or decrypted.status == "decryption failed":
        print(f"   GnuPG Status: {decrypted.status}")
        print("   Error: Possible bad passphrase, try again.")
        exit()

    # Clean decrypted bytes
    decrypted_bytes = decrypted.data
    decrypted_bytes = self.strip_junk(decrypted_bytes)

    decrypted_str = decrypted_bytes.decode("utf-8")

    # For debugging: save to a file
    with open("decrypted_debug.json", "w", encoding="utf-8") as f:
        f.write(decrypted_str)

    try:
        self.decrypted_file = json.loads(decrypted_str)
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        exit()

    self.vaults = self.decrypted_file["vaults"].items()

  
  def strip_junk(self, data: bytes) -> bytes:
    front_binaries_pattern = re.compile(rb'}PK.+', flags=re.DOTALL)
    back_binaries_pattern = re.compile(rb'^[^{]*', flags=re.DOTALL)
    cleaned = re.sub(front_binaries_pattern, b'', re.sub(back_binaries_pattern, b'', data))
    return cleaned


  def create_entry(self, entry):
    return Entry(entry)
  
