from datetime import datetime
from datetime import datetime

class Entry:
    def __init__(self, entry):
        # Defensive fetching of data parts
        data = entry.get("data", {})
        metadata = data.get("metadata", {})
        content = data.get("content", {})

        # Store all raw fields combined for dynamic usage later
        self.raw_data = {}
        # Merge metadata and content dicts into raw_data
        self.raw_data.update(metadata)
        self.raw_data.update(content)
        # Include top-level create and modify timestamps as well
        self.raw_data["createTime"] = entry.get("createTime")
        self.raw_data["modifyTime"] = entry.get("modifyTime")

        # Extract known fields with safe defaults
        self._name = metadata.get("name", "Unnamed Entry")

        # Robust username extraction (includes email, login, username, Email (aliases), etc)
        self._username = self._extract_username(content)

        # Escape special chars in password
        password_raw = content.get("password", "")
        self._password = self._escape_special_chars(password_raw)

        # URLs handling (first url + additional)
        urls = content.get("urls", [])
        self._urls = urls[0] if urls else ""
        self._add_urls = urls[1:] if len(urls) > 1 else None

        # Escape note text
        note_raw = metadata.get("note", "")
        self._note = self._escape_note_chars(note_raw)

        # TOTP URI
        self._totp = content.get("totpUri", "")

        # Timestamps as ISO format strings
        # If timestamps missing, fallback to now
        create_ts = entry.get("createTime") or datetime.now().timestamp()
        modify_ts = entry.get("modifyTime") or datetime.now().timestamp()
        self._createTime = datetime.fromtimestamp(create_ts).isoformat()
        self._modifyTime = datetime.fromtimestamp(modify_ts).isoformat()

    def _extract_username(self, content: dict) -> str:
        """
        Extract username/email/login etc, case-insensitive, from content keys.
        """
        # Check keys that contain 'username' or 'email' (case insensitive)
        for key, value in content.items():
            if isinstance(value, str) and value.strip():
                key_lower = key.lower()
                if "username" in key_lower or "email" in key_lower:
                    return value.strip()

        # Fallback to common alternative keys
        for fallback_key in ["login", "user"]:
            val = content.get(fallback_key, "")
            if isinstance(val, str) and val.strip():
                return val.strip()

        # No username/email found
        return ""

    def _escape_special_chars(self, text: str) -> str:
        """
        Escape backslashes, quotes, commas for XML-safe strings in password.
        """
        return text.replace("\\", "\\\\").replace("\"", "\\\"").replace(",", "\\,")

    def _escape_note_chars(self, text: str) -> str:
        """
        Escape newlines and quotes for XML-safe note strings.
        """
        return text.replace("\n", "\\n").replace("\"", "\\\"")

    # Properties for access

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def username(self) -> str:
        return self._username

    @property
    def password(self) -> str:
        return self._password

    @property
    def urls(self) -> str:
        return self._urls

    @property
    def add_urls(self):
        return self._add_urls

    @property
    def note(self) -> str:
        return self._note

    @property
    def totp(self) -> str:
        return self._totp

    @property
    def createTime(self) -> str:
        return self._createTime

    @property
    def modifyTime(self) -> str:
        return self._modifyTime
