import re
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
import pykeepass
from proton_to_keepass.config import Config

def sanitize_for_xml(text):
    if not text:
        return ""
    # Remove null bytes and control characters except \n, \r, and \t
    return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)

def extract_otp_secret(otp_uri: str) -> str:
    """
    Given an otpauth:// URI, extract the secret parameter (base32 string).
    """
    if not otp_uri or not otp_uri.startswith("otpauth://"):
        return otp_uri  # Return as-is if not an otpauth URI

    parsed = urlparse(otp_uri)
    query = parse_qs(parsed.query)
    secret_list = query.get("secret")
    if secret_list:
        return unquote(secret_list[0])
    else:
        return otp_uri  # fallback if no secret found

class KeePassManager():
    def __init__(self, config: Config, totp=False):
        self._config = config
        self._output_path = config.output_file_path if not totp else config.totp_output_file_path
        self._output_name = config.output_file_name if not totp else config.totp_output_file_name
        self._passkey = config.output_file_passkey if not totp else config.totp_output_file_passkey
        self._db = pykeepass.create_database(f'{self._output_path}/{self._output_name}', password=self._passkey)

    @property
    def root(self):
        return self._db.root_group

    def add_entry(self, group, entry):
        def safe_str(s):
            if not s:
                return ""
            # Remove null bytes and control chars except \n \r \t
            return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', str(s))

        base_name = safe_str(entry.name)
        username = safe_str(entry.username)
        password = safe_str(entry.password)

        # Add the main entry
        try:
            new_entry = self._db.add_entry(group, base_name, username, password)
        except Exception as e:
            if "already exists" in str(e):
                for attempt in range(10):
                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")
                    try:
                        new_entry = self._db.add_entry(group, f'{base_name}-{timestamp}', username, password)
                        break
                    except Exception as e2:
                        if "already exists" not in str(e2):
                            raise e2
                        time.sleep(0.001)
                else:
                    raise Exception(f"Could not add unique entry for '{base_name}' after 10 attempts")
            else:
                raise e

        new_entry.url = safe_str(entry.urls)
        new_entry.notes = safe_str(entry.note)

        new_entry._set_times_property("creation_time", entry.createTime)
        new_entry._set_times_property("last_modification_time", entry.modifyTime)

        if entry.totp:
            secret = extract_otp_secret(entry.totp)
            new_entry.otp = safe_str(secret)

        if entry.add_urls:
            if len(entry.add_urls) > 1:
                new_entry.set_custom_property("Additional URLs", "\n".join([safe_str(u) for u in entry.add_urls]))
            else:
                new_entry.set_custom_property("Additional URLs", safe_str(entry.add_urls[0]))

        # === Here’s the important part: add all other data fields dynamically ===
        # Assume `entry.raw_data` is a dict of all key-value pairs from ProtonPass raw entry data
        # If your Entry class doesn't have raw_data, modify it to include it, or
        # provide a method to expose all raw fields.

        if hasattr(entry, "raw_data") and isinstance(entry.raw_data, dict):
            standard_keys = {"name", "username", "password", "urls", "note", "totp", "createtime", "modifytime", "add_urls"}
            for key, value in entry.raw_data.items():
                if key.lower() in standard_keys:
                    continue  # skip known handled fields
                if value is None:
                    continue
                # For values that are lists, join them
                if isinstance(value, (list, tuple)):
                    value_str = "\n".join([safe_str(v) for v in value])
                else:
                    value_str = safe_str(value)
                if value_str:
                    # Use key as custom property name
                    new_entry.set_custom_property(safe_str(key), value_str)

    def create_group(self, group_name):
        return self._db.add_group(self.root, group_name)

    def save(self):
        self._db.save()
