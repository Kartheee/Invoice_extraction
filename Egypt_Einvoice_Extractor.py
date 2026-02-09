import os
import sys
import time
import threading
import queue
import base64
import json
import ctypes
import subprocess
import shutil
import atexit
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import pandas as pd
import re

# ================= SUPPRESS CUSTOMTKINTER CLOSE ERRORS =================
import tkinter as tk

_original_tk_destroy = tk.Tk.destroy


def _patched_destroy(self):
    """Patched destroy that suppresses after callback errors."""
    try:
        for after_id in self.tk.call('after', 'info'):
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
    except Exception:
        pass

    try:
        _original_tk_destroy(self)
    except Exception:
        pass


tk.Tk.destroy = _patched_destroy
# ================= END SUPPRESS ERRORS =================

# ================= CONFIG =================
APP_NAME = "EgyptEInvoiceExtractor"
ETA_BASE_URL = "https://invoicing.eta.gov.eg"
INVOICE_URL = "https://invoicing.eta.gov.eg/print/documents/{}"

# Security Configuration
DEFAULT_RETENTION_DAYS = 30
SECURE_FOLDER_NAME = "SecureStorage"
CHROME_PROFILE_NAME = "ChromeProfile"
METADATA_FILE = ".metadata.json"
AUDIT_LOG_FILE = ".security_audit.log"
CONFIG_FILE = "security_config.json"

# ================= ADMIN USER CONFIGURATION =================
ADMIN_USERNAME = "kartheee"
ADMIN_EMAIL = "kartheee@amazon.com"

# ================= WORKDOCS USER AUTHORIZATION CONFIG =================
AUTH_CONFIG_FILENAME = "authorized_users.json"
AUTH_CONFIG_FOLDER_NAME = "EgyptinvoiceextractApp"

WORKDOCS_DRIVE_LETTERS = ["W:", "X:", "Y:", "Z:", "D:", "E:", "F:"]

WORKDOCS_SEARCH_PATHS = [
    "My Documents",
    "MyDocuments",
    "",
    "Shared with me",
    "SharedWithMe",
    "Shared",
]

ONEDRIVE_PATTERNS = [
    "OneDrive - Amazon",
    "OneDrive - AMAZON",
    "OneDrive",
]

LOCAL_FALLBACK_FOLDER = "EgyptinvoiceextractApp"


# ================= PYINSTALLER PATH =================
def resource_path(rel_path):
    try:
        return os.path.join(sys._MEIPASS, rel_path)
    except Exception:
        return os.path.abspath(rel_path)


# ================= PASSWORD HASHING =================
def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = base64.b64encode(os.urandom(32)).decode('utf-8')

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 260000)
    password_hash = base64.b64encode(key).decode('utf-8')

    return password_hash, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash."""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == stored_hash


# ================= WORKDOCS USER AUTH MANAGER =================
class WorkDocsUserAuthManager:
    """Manages user authorization using WorkDocs-stored config file."""

    def __init__(self):
        self.current_user = os.getenv("USERNAME", "").lower()
        self.current_domain = os.getenv("USERDOMAIN", "")
        self.local_config_path = None
        self.config_data = None
        self.is_admin = False
        self.is_owner = False
        self.can_write = False
        self.auth_status = "unknown"
        self.auth_message = ""
        self.config_source = "none"

        self._find_config_path()

    def is_primary_admin(self) -> bool:
        """Check if current user is the primary admin."""
        return self.current_user.lower() == ADMIN_USERNAME.lower()

    def _find_config_path(self):
        """Find the config file in WorkDocs, OneDrive, or local fallback."""
        for drive in WORKDOCS_DRIVE_LETTERS:
            drive_root = drive + "\\"
            if not os.path.exists(drive_root):
                continue

            for search_path in WORKDOCS_SEARCH_PATHS:
                if search_path:
                    folder_path = os.path.join(drive_root, search_path, AUTH_CONFIG_FOLDER_NAME)
                    config_path = os.path.join(folder_path, AUTH_CONFIG_FILENAME)
                else:
                    folder_path = os.path.join(drive_root, AUTH_CONFIG_FOLDER_NAME)
                    config_path = os.path.join(folder_path, AUTH_CONFIG_FILENAME)

                if os.path.exists(config_path):
                    self.local_config_path = config_path
                    self.is_owner = self._is_owner_path(search_path)
                    self.can_write = self._check_write_access(folder_path)
                    self.config_source = f"workdocs_{drive}"
                    return

                if os.path.exists(folder_path):
                    self.local_config_path = config_path
                    self.is_owner = self._is_owner_path(search_path)
                    self.can_write = self._check_write_access(folder_path)
                    self.config_source = f"workdocs_{drive}"
                    return

        if os.path.exists("W:\\"):
            my_docs_path = "W:\\My Documents"
            if os.path.exists(my_docs_path):
                self.local_config_path = os.path.join(my_docs_path, AUTH_CONFIG_FOLDER_NAME, AUTH_CONFIG_FILENAME)
                self.is_owner = True
                self.can_write = True
                self.config_source = "workdocs_W:"
                return
            else:
                self.local_config_path = os.path.join("W:\\", AUTH_CONFIG_FOLDER_NAME, AUTH_CONFIG_FILENAME)
                self.is_owner = True
                self.can_write = True
                self.config_source = "workdocs_W:"
                return

        user_profile = os.getenv("USERPROFILE", "")
        for pattern in ONEDRIVE_PATTERNS:
            onedrive_base = os.path.join(user_profile, pattern)
            if os.path.exists(onedrive_base):
                folder_path = os.path.join(onedrive_base, AUTH_CONFIG_FOLDER_NAME)
                config_path = os.path.join(folder_path, AUTH_CONFIG_FILENAME)

                if os.path.exists(config_path) or os.path.exists(onedrive_base):
                    self.local_config_path = config_path
                    self.is_owner = True
                    self.can_write = True
                    self.config_source = "onedrive"
                    return

        local_app_data = os.getenv("LOCALAPPDATA", "")
        if local_app_data:
            folder_path = os.path.join(local_app_data, APP_NAME, AUTH_CONFIG_FOLDER_NAME)
            config_path = os.path.join(folder_path, AUTH_CONFIG_FILENAME)
            self.local_config_path = config_path
            self.is_owner = True
            self.can_write = True
            self.config_source = "local"
            return

    def _is_owner_path(self, search_path: str) -> bool:
        """Check if the path indicates ownership (not shared)."""
        shared_indicators = ["Shared", "shared"]
        search_lower = search_path.lower()

        for indicator in shared_indicators:
            if indicator.lower() in search_lower:
                return False
        return True

    def _check_write_access(self, folder_path: str) -> bool:
        """Check if we have write access to the folder."""
        try:
            if not os.path.exists(folder_path):
                os.makedirs(folder_path, exist_ok=True)
                return True

            test_file = os.path.join(folder_path, ".write_test")
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                return True
            except:
                return False
        except:
            return False

    def _load_config(self) -> Optional[Dict]:
        """Load config from local file."""
        if not self.local_config_path:
            return None

        try:
            if os.path.exists(self.local_config_path):
                with open(self.local_config_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
        except Exception:
            pass
        return None

    def _save_config(self, data: Dict) -> bool:
        """Save config to local file."""
        if not self.local_config_path or not self.can_write:
            return False

        try:
            os.makedirs(os.path.dirname(self.local_config_path), exist_ok=True)
            with open(self.local_config_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def load_config(self) -> bool:
        """Load configuration."""
        self.config_data = self._load_config()
        return self.config_data is not None

    def config_exists(self) -> bool:
        """Check if configuration file exists."""
        if not self.local_config_path:
            return False
        return os.path.exists(self.local_config_path)

    def is_first_time_setup(self) -> bool:
        """Check if this is the first time setup."""
        if not self.load_config():
            return True
        if not self.config_data:
            return True
        if "authorized_users" not in self.config_data:
            return True
        if len(self.config_data.get("authorized_users", [])) == 0:
            return True
        return False

    def setup_first_admin(self, password: str) -> Tuple[bool, str]:
        """Set up the first admin user."""
        if not self.can_write:
            return False, (
                f"Cannot write to config file.\n\n"
                f"Path: {self.local_config_path}\n\n"
                f"Make sure:\n"
                f"1. WorkDocs Drive (W:) is installed and synced\n"
                f"2. You have write access to 'My Documents'"
            )

        password_hash, salt = hash_password(password)

        self.config_data = {
            "config_version": "1.0",
            "created_at": datetime.now().isoformat(),
            "created_by": f"{self.current_domain}\\{self.current_user}",
            "admin_password_hash": password_hash,
            "admin_password_salt": salt,
            "authorized_users": [
                {
                    "username": self.current_user.lower(),
                    "domain": self.current_domain,
                    "full_name": "Administrator",
                    "added_by": "SYSTEM",
                    "added_on": datetime.now().isoformat(),
                    "is_admin": True
                }
            ],
            "access_log": []
        }

        if self._save_config(self.config_data):
            self.is_admin = True
            return True, "Admin setup complete!"
        else:
            return False, f"Failed to save configuration to:\n{self.local_config_path}"

    def check_authorization(self) -> Tuple[bool, str]:
        """Check if current user is authorized."""
        if self.is_primary_admin():
            if not self.config_exists():
                self.auth_status = "admin_setup_required"
                self.auth_message = "First time setup. Please set up your admin password."
                return False, self.auth_message

            if not self.load_config():
                self.auth_status = "config_error"
                self.auth_message = "Could not load configuration file."
                return False, self.auth_message

            self.is_admin = True
            self.auth_status = "authorized"
            self.auth_message = f"Welcome, Administrator ({ADMIN_USERNAME})!"
            self._log_access("ACCESS_GRANTED", f"Admin user {self.current_user} authorized")
            return True, self.auth_message

        if not self.config_exists():
            self.auth_status = "no_config"
            self.auth_message = (
                f"You don't have access to this application.\n\n"
                f"Please contact the administrator:\n"
                f"📧 {ADMIN_EMAIL}"
            )
            return False, self.auth_message

        if not self.load_config():
            self.auth_status = "config_error"
            self.auth_message = (
                f"Could not load configuration file.\n\n"
                f"Please contact the administrator:\n"
                f"📧 {ADMIN_EMAIL}"
            )
            return False, self.auth_message

        if not self.config_data or "authorized_users" not in self.config_data:
            self.auth_status = "invalid_config"
            self.auth_message = (
                f"Invalid configuration file.\n\n"
                f"Please contact the administrator:\n"
                f"📧 {ADMIN_EMAIL}"
            )
            return False, self.auth_message

        authorized_users = self.config_data.get("authorized_users", [])

        for user in authorized_users:
            if user.get("username", "").lower() == self.current_user.lower():
                self.is_admin = user.get("is_admin", False)
                self.auth_status = "authorized"
                self.auth_message = f"Welcome, {user.get('full_name', self.current_user)}!"
                self._log_access("ACCESS_GRANTED", f"User {self.current_user} authorized")
                return True, self.auth_message

        self.auth_status = "unauthorized"
        self.auth_message = (
            f"User '{self.current_user}' is not authorized.\n\n"
            f"Please contact the administrator:\n"
            f"📧 {ADMIN_EMAIL}"
        )
        self._log_access("ACCESS_DENIED", f"User {self.current_user} not authorized")
        return False, self.auth_message

    def _log_access(self, event_type: str, message: str):
        """Log access attempt."""
        if not self.config_data:
            return

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            "user": f"{self.current_domain}\\{self.current_user}",
            "message": message
        }

        if "access_log" not in self.config_data:
            self.config_data["access_log"] = []

        self.config_data["access_log"].append(log_entry)

        if len(self.config_data["access_log"]) > 100:
            self.config_data["access_log"] = self.config_data["access_log"][-100:]

        if self.can_write:
            self._save_config(self.config_data)

    def verify_admin_password(self, password: str) -> bool:
        """Verify admin password."""
        if not self.config_data:
            return False

        stored_hash = self.config_data.get("admin_password_hash", "")
        salt = self.config_data.get("admin_password_salt", "")

        if not stored_hash or not salt:
            return False

        return verify_password(password, stored_hash, salt)

    def add_user(self, username: str, full_name: str = "", is_admin: bool = False) -> Tuple[bool, str]:
        """Add a new authorized user."""
        if not self.can_write:
            return False, "Cannot write to config file.\nOnly the config owner can add users."

        if not self.config_data:
            return False, "Configuration not loaded"

        username = username.lower().strip()

        if not username:
            return False, "Username cannot be empty"

        for user in self.config_data.get("authorized_users", []):
            if user.get("username", "").lower() == username:
                return False, f"User '{username}' already exists"

        new_user = {
            "username": username,
            "domain": self.current_domain,
            "full_name": full_name or username,
            "added_by": self.current_user,
            "added_on": datetime.now().isoformat(),
            "is_admin": is_admin
        }

        self.config_data["authorized_users"].append(new_user)
        self._log_access("USER_ADDED", f"User {username} added by {self.current_user}")

        if self._save_config(self.config_data):
            return True, f"User '{username}' added successfully!"
        else:
            return False, "Failed to save configuration"

    def remove_user(self, username: str) -> Tuple[bool, str]:
        """Remove an authorized user."""
        if not self.can_write:
            return False, "Cannot write to config file.\nOnly the config owner can remove users."

        if not self.config_data:
            return False, "Configuration not loaded"

        username = username.lower().strip()

        if username.lower() == ADMIN_USERNAME.lower():
            return False, f"Cannot remove the primary administrator ({ADMIN_USERNAME})"

        admin_count = sum(1 for u in self.config_data.get("authorized_users", []) if u.get("is_admin", False))

        for i, user in enumerate(self.config_data.get("authorized_users", [])):
            if user.get("username", "").lower() == username:
                if user.get("is_admin", False) and admin_count <= 1:
                    return False, "Cannot remove the only admin user"

                self.config_data["authorized_users"].pop(i)
                self._log_access("USER_REMOVED", f"User {username} removed by {self.current_user}")

                if self._save_config(self.config_data):
                    return True, f"User '{username}' removed successfully"
                else:
                    return False, "Failed to save configuration"

        return False, f"User '{username}' not found"

    def get_authorized_users(self) -> List[Dict]:
        """Get list of authorized users."""
        if not self.config_data:
            return []
        return self.config_data.get("authorized_users", [])

    def get_access_log(self) -> List[Dict]:
        """Get access log entries."""
        if not self.config_data:
            return []
        return self.config_data.get("access_log", [])

    def change_admin_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change admin password."""
        if not self.can_write:
            return False, "Cannot write to config file"

        if not self.verify_admin_password(old_password):
            return False, "Current password is incorrect"

        password_hash, salt = hash_password(new_password)
        self.config_data["admin_password_hash"] = password_hash
        self.config_data["admin_password_salt"] = salt

        self._log_access("PASSWORD_CHANGED", f"Admin password changed by {self.current_user}")

        if self._save_config(self.config_data):
            return True, "Password changed successfully"
        else:
            return False, "Failed to save configuration"

    def get_config_info(self) -> Dict[str, Any]:
        """Get information about config file location."""
        return {
            "local_path": self.local_config_path,
            "can_write": self.can_write,
            "is_owner": self.is_owner,
            "config_source": self.config_source,
            "current_user": self.current_user,
            "is_admin": self.is_admin,
            "is_primary_admin": self.is_primary_admin(),
        }


# ================= WINDOWS EFS ENCRYPTION =================
class WindowsTransparentSecurity:
    """Implements transparent security using Windows built-in features."""

    def __init__(self):
        self.advapi32 = ctypes.windll.advapi32
        self.kernel32 = ctypes.windll.kernel32
        self.current_user = os.getenv("USERNAME")
        self.current_domain = os.getenv("USERDOMAIN", "")

    def encrypt_file(self, filepath: str) -> Tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "File does not exist"
        result = self.advapi32.EncryptFileW(filepath)
        if result:
            return True, "File encrypted successfully"
        else:
            error_code = self.kernel32.GetLastError()
            return False, f"Encryption failed (Error: {error_code})"

    def encrypt_folder(self, folder_path: str) -> Tuple[bool, str]:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, exist_ok=True)
        result = self.advapi32.EncryptFileW(folder_path)
        if result:
            return True, "Folder set to auto-encrypt"
        else:
            error_code = self.kernel32.GetLastError()
            return False, f"Folder encryption failed (Error: {error_code})"

    def decrypt_file(self, filepath: str) -> Tuple[bool, str]:
        result = self.advapi32.DecryptFileW(filepath, 0)
        if result:
            return True, "File decrypted successfully"
        else:
            error_code = self.kernel32.GetLastError()
            return False, f"Decryption failed (Error: {error_code})"

    def is_encrypted(self, filepath: str) -> bool:
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            return bool(attrs & 0x4000)
        except Exception:
            return False

    def check_efs_available(self) -> Tuple[bool, str]:
        try:
            drive = os.path.splitdrive(os.getenv("LOCALAPPDATA"))[0] + "\\"
            fs_name = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetVolumeInformationW(
                drive, None, 0, None, None, None, fs_name, 256
            )
            if fs_name.value != "NTFS":
                return False, "EFS requires NTFS file system"

            test_dir = os.path.join(os.getenv("TEMP"), "efs_test")
            os.makedirs(test_dir, exist_ok=True)
            test_file = os.path.join(test_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            result = self.advapi32.EncryptFileW(test_file)
            try:
                os.remove(test_file)
                os.rmdir(test_dir)
            except:
                pass
            if result:
                return True, "EFS is available and working"
            else:
                return False, "EFS not available (Windows Home edition?)"
        except Exception as e:
            return False, f"EFS check failed: {e}"


# ================= SECURE STORAGE MANAGER =================
class TransparentSecureStorage:
    """Manages secure storage with EFS encryption."""

    def __init__(self, base_path: Optional[str] = None):
        self.efs = WindowsTransparentSecurity()
        self.base_path = base_path or self._get_default_path()
        self.secure_folder = os.path.join(self.base_path, SECURE_FOLDER_NAME)
        self.chrome_profile_folder = os.path.join(self.secure_folder, CHROME_PROFILE_NAME)
        self.metadata_path = os.path.join(self.secure_folder, METADATA_FILE)
        self.audit_log_path = os.path.join(self.secure_folder, AUDIT_LOG_FILE)
        self.config_path = os.path.join(self.base_path, CONFIG_FILE)
        self.efs_available = False
        self.efs_status_message = ""
        self.config = self._load_config()
        self._initialize_storage()

    def _get_default_path(self) -> str:
        return os.path.join(os.getenv("LOCALAPPDATA"), APP_NAME)

    def _load_config(self) -> Dict[str, Any]:
        default_config = {
            "retention_days": DEFAULT_RETENTION_DAYS,
            "auto_delete_enabled": True,
            "audit_logging_enabled": True,
            "efs_encryption_enabled": True,
            "created_at": datetime.now().isoformat(),
            "created_by": os.getenv("USERNAME")
        }
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
            except Exception:
                pass
        return default_config

    def save_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def _initialize_storage(self):
        os.makedirs(self.secure_folder, exist_ok=True)
        self._set_folder_permissions(self.secure_folder)
        self.efs_available, self.efs_status_message = self.efs.check_efs_available()
        if self.efs_available and self.config.get("efs_encryption_enabled", True):
            success, msg = self.efs.encrypt_folder(self.secure_folder)
            if success:
                self._audit_log("INIT", "EFS encryption enabled on secure folder")
            else:
                self._audit_log("WARNING", f"Could not enable EFS: {msg}")

        os.makedirs(self.chrome_profile_folder, exist_ok=True)
        self._set_folder_permissions(self.chrome_profile_folder)
        if self.efs_available and self.config.get("efs_encryption_enabled", True):
            self.efs.encrypt_folder(self.chrome_profile_folder)
            self._audit_log("INIT", "EFS encryption enabled on Chrome profile folder")

        if not os.path.exists(self.metadata_path):
            self._save_metadata({"extractions": {}, "files": {}})
        self._audit_log("INIT", f"Secure storage initialized at {self.secure_folder}")

    def _set_folder_permissions(self, folder: str):
        try:
            username = os.getenv("USERNAME")
            subprocess.run(['icacls', folder, '/inheritance:r'],
                           capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['icacls', folder, '/grant:r', f'{username}:(OI)(CI)F'],
                           capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['icacls', folder, '/grant:r', 'SYSTEM:(OI)(CI)F'],
                           capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self._audit_log("PERMISSIONS", f"Folder restricted to user: {username}")
        except Exception as e:
            self._audit_log("WARNING", f"Permission setup issue: {e}")

    def _audit_log(self, event_type: str, message: str):
        if not self.config.get("audit_logging_enabled", True):
            return
        timestamp = datetime.now().isoformat()
        user = os.getenv("USERNAME")
        entry = f"[{timestamp}] [{event_type}] [{user}] {message}\n"
        try:
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(entry)
        except Exception:
            pass

    def _load_metadata(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path, 'r') as f:
                    data = json.load(f)
                    if "extractions" not in data:
                        data["extractions"] = {}
                    if "files" not in data:
                        data["files"] = {}
                    return data
        except Exception:
            pass
        return {"extractions": {}, "files": {}}

    def _save_metadata(self, metadata: Dict[str, Any]):
        try:
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception:
            pass

    def get_output_filepath(self, input_filename: str) -> str:
        """Generate output filepath in secure storage with datetime suffix."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        output_filename = f"{base_name}_Extracted_{timestamp}.xlsx"
        return os.path.join(self.secure_folder, output_filename)

    def log_extraction(self, excel_file: str, output_file: str, record_count: int):
        """Log an extraction session."""
        metadata = self._load_metadata()
        extraction_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        metadata["extractions"][extraction_id] = {
            "created_at": datetime.now().isoformat(),
            "created_by": os.getenv("USERNAME"),
            "input_file": excel_file,
            "output_file": output_file,
            "record_count": record_count
        }
        self._save_metadata(metadata)
        self._audit_log("EXTRACTION", f"Extracted {record_count} records to {output_file}")

    def get_stats(self) -> Dict[str, Any]:
        metadata = self._load_metadata()
        extractions = metadata.get("extractions", {})
        return {
            "total_extractions": len(extractions),
            "total_records": sum(e.get("record_count", 0) for e in extractions.values()),
            "efs_available": self.efs_available,
            "efs_status": self.efs_status_message,
            "retention_days": self.config.get("retention_days", DEFAULT_RETENTION_DAYS),
            "secure_folder": self.secure_folder,
            "current_user": os.getenv("USERNAME")
        }

    def open_folder(self):
        if not os.path.exists(self.secure_folder):
            os.makedirs(self.secure_folder, exist_ok=True)
        os.startfile(self.secure_folder)


# ================= GLOBAL FLAGS =================
pause_event = threading.Event()
cancel_event = threading.Event()
pause_event.set()

log_queue = queue.Queue()
log_lock = threading.Lock()  # FIX FOR ISSUE 1: Thread lock for logging
secure_storage: Optional[TransparentSecureStorage] = None
user_auth: Optional[WorkDocsUserAuthManager] = None


def ui_log(msg):
    """Thread-safe logging to UI queue."""
    with log_lock:  # FIX FOR ISSUE 1: Use lock for thread safety
        log_queue.put(msg)


# ================= CHROME HELPER FUNCTIONS =================
def get_profile_dir():
    """Get Chrome profile directory - inside secure storage for encryption."""
    if secure_storage:
        return secure_storage.chrome_profile_folder
    return os.path.join(os.getenv("LOCALAPPDATA"), APP_NAME, SECURE_FOLDER_NAME, CHROME_PROFILE_NAME)


def is_chrome_running() -> bool:
    """Check if Chrome is running."""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq chrome.exe'],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return 'chrome.exe' in result.stdout.lower()
    except:
        return False


def kill_chrome_processes():
    """Kill all Chrome processes."""
    try:
        subprocess.run(
            ['taskkill', '/F', '/IM', 'chrome.exe'],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(2)
    except:
        pass


def clear_profile_locks():
    """Clear Chrome profile lock files."""
    profile_dir = get_profile_dir()
    lock_files = [
        os.path.join(profile_dir, "SingletonLock"),
        os.path.join(profile_dir, "SingletonSocket"),
        os.path.join(profile_dir, "SingletonCookie"),
        os.path.join(profile_dir, "lockfile"),
    ]
    for lock_file in lock_files:
        try:
            if os.path.exists(lock_file):
                os.remove(lock_file)
        except:
            pass


def force_delete_chrome_profile() -> Tuple[bool, str]:
    """NUCLEAR OPTION: Completely delete the Chrome profile folder."""
    profile_dir = get_profile_dir()

    if is_chrome_running():
        kill_chrome_processes()
        time.sleep(3)

    if is_chrome_running():
        return False, "Chrome is still running - please close it manually"

    time.sleep(1)
    clear_profile_locks()
    time.sleep(0.5)

    if not os.path.exists(profile_dir):
        os.makedirs(profile_dir, exist_ok=True)
        if secure_storage and secure_storage.efs_available:
            secure_storage.efs.encrypt_folder(profile_dir)
        return True, "No profile exists - created fresh"

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            shutil.rmtree(profile_dir)
            os.makedirs(profile_dir, exist_ok=True)

            if secure_storage and secure_storage.efs_available:
                secure_storage.efs.encrypt_folder(profile_dir)
                secure_storage._set_folder_permissions(profile_dir)

            if secure_storage:
                secure_storage._audit_log("PROFILE_DELETE", "Chrome profile completely deleted")

            return True, "Profile completely deleted - fresh start"

        except PermissionError:
            if attempt < max_attempts - 1:
                time.sleep(2)
                kill_chrome_processes()
                time.sleep(1)
            else:
                return False, "Permission denied - Chrome may still be running"

        except Exception as e:
            if attempt < max_attempts - 1:
                time.sleep(1)
            else:
                return False, f"Error: {str(e)[:50]}"

    return False, "Failed after multiple attempts"


def clear_session_on_exit():
    """Clear session when app exits."""
    try:
        if is_chrome_running():
            kill_chrome_processes()
            time.sleep(2)

        success, msg = force_delete_chrome_profile()

        if secure_storage:
            secure_storage._audit_log("APP_EXIT", f"Exit cleanup: {msg}")

        return success
    except Exception as e:
        if secure_storage:
            secure_storage._audit_log("APP_EXIT_ERROR", f"Cleanup error: {e}")
        return False


atexit.register(clear_session_on_exit)


# ================= CREATE DRIVER =================
def create_driver(headless=True):
    """Create Chrome WebDriver with password saving DISABLED."""
    profile = get_profile_dir()
    os.makedirs(profile, exist_ok=True)

    clear_profile_locks()

    opts = Options()
    opts.add_argument(f"--user-data-dir={profile}")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-plugins")
    opts.add_argument("--remote-debugging-port=9222")

    opts.add_argument("--disable-save-password-bubble")
    opts.add_argument("--disable-translate")
    opts.add_argument("--disable-features=PasswordManager")
    opts.add_argument("--disable-features=AutofillServerCommunication")
    opts.add_argument("--disable-features=AutofillCreditCardUpload")
    opts.add_argument("--password-store=basic")
    opts.add_argument("--disable-sync")
    opts.add_argument("--disable-background-networking")

    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    prefs = {
        "credentials_enable_service": False,
        "profile.password_manager_enabled": False,
        "profile.default_content_setting_values.notifications": 2,
        "autofill.profile_enabled": False,
        "autofill.credit_card_enabled": False,
        "autofill.address_enabled": False,
        "sync.suppress_start": True,
        "signin.allowed": False,
    }
    opts.add_experimental_option("prefs", prefs)

    if headless:
        opts.add_argument("--headless=new")

    try:
        driver = webdriver.Chrome(options=opts)
        return driver
    except Exception as e:
        raise RuntimeError(f"Failed to start Chrome: {str(e)}")


# ================= ETA SESSION CHECK =================
def check_eta_session():
    """Verify that ETA portal session is active."""
    driver = None
    try:
        ui_log("🌐 Verifying ETA portal session...")
        driver = create_driver(headless=True)
        driver.get(ETA_BASE_URL)
        time.sleep(5)

        current_url = driver.current_url.lower()
        page_source = driver.page_source.lower()

        ui_log(f"📍 Current URL: {driver.current_url}")

        if "login" in current_url or "signin" in current_url or "auth" in current_url:
            raise RuntimeError(
                "ETA Portal authentication required.\n\n"
                "Please login to ETA portal in Chrome first."
            )

        if "password" in page_source and ("username" in page_source or "email" in page_source):
            raise RuntimeError(
                "ETA Portal login page detected.\n\n"
                "Please login to ETA portal first using the Chrome profile."
            )

        ui_log("✅ ETA portal session verified")
        return True

    except RuntimeError:
        raise
    except Exception as e:
        ui_log(f"⚠️ Session check error: {str(e)}")
        return True
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass


# =========================================================
# INVOICE PARSER
# =========================================================
def parse_invoice_text(full_text, uuid):
    data = {"UUID": uuid}

    def rx(p, text=None):
        m = re.search(p, text or full_text, re.DOTALL)
        return m.group(1).strip() if m else "N/A"

    data["Document Type"] = rx(r"(Credit Note|Invoice|Debit Note)")
    data["Internal ID"] = rx(r"Internal ID[:\s]+([^\s\n]+)")
    data["Submission Date"] = rx(r"Submission Date[:\s]+([0-9/]+\s+[0-9:]+\s+[AP]M)")
    data["Issuance Date"] = rx(r"Issuance Date[:\s]+([0-9/]+\s+[0-9:]+\s+[AP]M)")
    data["Status"] = rx(r"Status[:\s]+(?:\S+\s+)?(\w+)")
    data["Registration Number"] = rx(r"Registration Number[:\s]+(\d+)")
    data["Issuer RIN"] = rx(r"Issuer RIN[:\s]+(\d+)")

    issuer_section = re.search(r"Issuer \(from\)(.*?)(?=Receiver \(to\))", full_text, re.DOTALL)
    if issuer_section:
        issuer_text = issuer_section.group(1)
        data["Issuer Name"] = rx(r"Name\s+([^\n]+)", issuer_text)
        data["Issuer Registration Number"] = rx(r"Registration Number\s+(\d+)", issuer_text)
        data["Issuer Branch Address"] = rx(
            r"Branch Address\s+([^\n]+(?:\n[^\n]+)*?)(?=\nTax Activity Code|\nType)",
            issuer_text
        ).replace("\n", " ")
        data["Issuer Type"] = rx(r"Type\s+([^\n]+)", issuer_text)
    else:
        data["Issuer Name"] = "N/A"
        data["Issuer Registration Number"] = "N/A"
        data["Issuer Branch Address"] = "N/A"
        data["Issuer Type"] = "N/A"

    data["Issuer Tax Activity Code"] = rx(r"Tax Activity Code\s+(\d+)")

    receiver_section = re.search(r"Receiver \(to\)(.*?)(?=Order Details)", full_text, re.DOTALL)
    if receiver_section:
        receiver_text = receiver_section.group(1)
        data["Receiver Name"] = rx(r"Name\s+([^\n]+)", receiver_text)
        data["Receiver Registration Number"] = rx(r"Registration Number\s+(\d+)", receiver_text)
        data["Receiver Type"] = rx(r"Type\s+([^\n]+)", receiver_text)
        data["Receiver Address"] = rx(
            r"Address\s+([^\n]+(?:\n[^\n]+)*?)(?=\nOrder Details|$)",
            receiver_text
        ).replace("\n", " ")
    else:
        data["Receiver Name"] = "N/A"
        data["Receiver Registration Number"] = "N/A"
        data["Receiver Type"] = "N/A"
        data["Receiver Address"] = "N/A"

    data["Purchase Order Reference"] = rx(r"Purchase Order Reference\s+([^\n]+)")
    data["Sales Order Reference"] = rx(r"Sales Order Reference\s+([^\n]+)")
    data["Purchase Order Description"] = rx(r"Purchase Order Description\s+([^\n]+)")
    data["Sales Order Description"] = rx(r"Sales Order Description\s+([^\n]+)")
    data["Proforma Invoice Number"] = rx(r"Proforma Invoice Number\s+([^\n]+)")

    data["Total Sales (EGP)"] = rx(r"Total Sales\s*\(EGP\)\s+([\d,.]+)")
    data["Total Discount (EGP)"] = rx(r"Total Discount\s*\(EGP\)\s+([\d,.]+)")
    data["Total Items Discount (EGP)"] = rx(r"Total Items Discount\s*\(EGP\)\s+([\d,.]+)")
    data["Value added Tax (EGP)"] = rx(r"Value added Tax\s*\(EGP\)\s+([\d,.]+)")
    data["Extra Invoice Discounts (EGP)"] = rx(r"Extra Invoice Discounts\s*\(EGP\)\s+([\d,.]+)")
    data["Total Amount (EGP)"] = rx(r"Total Amount\s*\(EGP\)\s+([\d,.]+)")
    data["Withholding Tax (WHT) (EGP)"] = rx(r"Withholding Tax\s*\(WHT\)\s*\(EGP\)\s+([\d,.]+)")
    data["Table tax (percentage) (EGP)"] = rx(r"Table tax\s*\(\s*percentage\s*\)\s*\(EGP\)\s+([\d,.]+)")

    data["Total Sales (USD)"] = rx(r"Total Sales\s*\(USD\)\s+([\d,.]+)")
    data["Total Discount (USD)"] = rx(r"Total Discount\s*\(USD\)\s+([\d,.]+)")
    data["Total Items Discount (USD)"] = rx(r"Total Items Discount\s*\(USD\)\s+([\d,.]+)")
    data["Value added Tax (USD)"] = rx(r"Value added Tax\s*\(USD\)\s+([\d,.]+)")
    data["Extra Invoice Discounts (USD)"] = rx(r"Extra Invoice Discounts\s*\(USD\)\s+([\d,.]+)")
    data["Total Amount (USD)"] = rx(r"Total Amount\s*\(USD\)\s+([\d,.]+)")
    data["Withholding Tax (WHT) (USD)"] = rx(r"Withholding Tax\s*\(WHT\)\s*\(USD\)\s+([\d,.]+)")
    data["Table tax (percentage) (USD)"] = rx(r"Table tax\s*\(\s*percentage\s*\)\s*\(USD\)\s+([\d,.]+)")

    data["Referenced documents"] = rx(r"Referenced documents\s+([A-Z0-9]+)")
    data["Invoice Status"] = ""
    data["Invoice Reference"] = ""
    data["Invoice Type"] = ""

    return data


# ================= EXTRACTION =================
def run_extraction(excel, output, progress_cb, time_cb):
    global secure_storage

    ui_log(f"📂 Loading Excel file: {excel}")

    df = pd.read_excel(excel)
    uuid_col = next(c for c in df.columns if c.strip().upper() == "UUID")
    uuids = df[uuid_col].dropna().astype(str).tolist()

    total = len(uuids)
    ui_log(f"📋 Found {total} UUIDs to process")

    if total == 0:
        raise ValueError("No UUIDs found in the Excel file!")

    done = 0
    skipped = 0
    start_time = time.time()
    results = []

    ui_log("🚀 Starting Chrome driver...")
    driver = create_driver(headless=True)
    ui_log("✅ Chrome driver started")

    try:
        for idx, u in enumerate(uuids):
            if cancel_event.is_set():
                ui_log("❌ Extraction cancelled by user")
                break
            pause_event.wait()

            u = u.strip()
            if not u:
                continue

            ui_log(f"📄 [{idx + 1}/{total}] Processing UUID: {u}")

            try:
                driver.get(INVOICE_URL.format(u))
                time.sleep(4)

                current_url = driver.current_url
                ui_log(f"📍 Current URL: {current_url}")

                if "login" in current_url.lower() or "signin" in current_url.lower():
                    ui_log(f"⚠️ Redirected to login page for UUID: {u}")
                    skipped += 1
                    continue

                text = driver.execute_script("return document.body.innerText")
                page_length = len(text.strip())
                ui_log(f"📝 Page content length: {page_length} characters")

                if page_length < 100:
                    ui_log(f"⚠️ Skipped UUID (page not loaded): {u}")
                    skipped += 1
                    continue

                parsed_data = parse_invoice_text(text, u)
                results.append(parsed_data)
                done += 1

                pd.DataFrame(results).to_excel(output, index=False)
                ui_log(f"✔ Extracted and saved: {done}/{total} (Internal ID: {parsed_data.get('Internal ID', 'N/A')})")

            except Exception as e:
                ui_log(f"❌ Error processing {u}: {str(e)}")
                skipped += 1

            processed = done + skipped
            elapsed = time.time() - start_time
            remaining = total - processed
            eta = (elapsed / processed) * remaining if processed > 0 else 0

            progress_cb(processed / total)
            time_cb(elapsed, eta)

        if secure_storage:
            secure_storage.log_extraction(excel, output, done)

        ui_log("")
        ui_log("=" * 50)
        ui_log(f"📊 EXTRACTION COMPLETE")
        ui_log(f"   ├── Total UUIDs: {total}")
        ui_log(f"   ├── Successful: {done}")
        ui_log(f"   ├── Skipped: {skipped}")
        ui_log(f"   └── Output: {output}")
        ui_log("=" * 50)

    except Exception as e:
        ui_log(f"❌ Extraction error: {str(e)}")
        raise
    finally:
        ui_log("🔄 Closing Chrome driver...")
        try:
            driver.quit()
        except:
            pass
        ui_log("✅ Chrome driver closed")


# ================= FIRST TIME SETUP DIALOG =================
class FirstTimeSetupDialog(ctk.CTkToplevel):
    """Dialog for first-time admin setup."""

    def __init__(self, parent, auth_manager: WorkDocsUserAuthManager):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setup_complete = False

        self.title("First Time Setup - Administrator")
        self.geometry("550x650")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 550) // 2
        y = (self.winfo_screenheight() - 650) // 2
        self.geometry(f"550x650+{x}+{y}")

        self._create_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, lambda: self.password_entry.focus())

    def _create_widgets(self):
        header = ctk.CTkFrame(self, fg_color="#1565c0", corner_radius=0, height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🔐 First Time Setup", font=("Segoe UI", 24, "bold"), text_color="white").pack(expand=True)

        self.content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=25, pady=15)

        ctk.CTkLabel(self.content_frame, text="Welcome! You are the Primary Administrator.", font=("Segoe UI", 14, "bold"), text_color="#2e7d32").pack(pady=(10, 20))

        user_frame = ctk.CTkFrame(self.content_frame, fg_color="#e3f2fd", corner_radius=10)
        user_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(user_frame, text=f"⭐ Username: {self.auth_manager.current_user}", font=("Segoe UI", 14, "bold"), text_color="#1565c0").pack(pady=(15, 5))
        ctk.CTkLabel(user_frame, text=f"Domain: {self.auth_manager.current_domain}", font=("Segoe UI", 11), text_color="#666").pack(pady=(0, 5))
        ctk.CTkLabel(user_frame, text="Role: Primary Administrator", font=("Segoe UI", 11, "bold"), text_color="#e65100").pack(pady=(0, 15))

        pw_frame = ctk.CTkFrame(self.content_frame, fg_color="#fff8e1", corner_radius=10)
        pw_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(pw_frame, text="🔑 Set Admin Password", font=("Segoe UI", 14, "bold"), text_color="#f57c00").pack(pady=(15, 15))
        ctk.CTkLabel(pw_frame, text="Password (minimum 6 characters):", font=("Segoe UI", 12)).pack(anchor="w", padx=30)

        self.password_entry = ctk.CTkEntry(pw_frame, width=350, height=45, show="●", placeholder_text="Enter password", font=("Segoe UI", 13))
        self.password_entry.pack(pady=(8, 15))

        ctk.CTkLabel(pw_frame, text="Confirm Password:", font=("Segoe UI", 12)).pack(anchor="w", padx=30)

        self.confirm_entry = ctk.CTkEntry(pw_frame, width=350, height=45, show="●", placeholder_text="Confirm password", font=("Segoe UI", 13))
        self.confirm_entry.pack(pady=(8, 20))

        self.password_entry.bind("<Return>", lambda e: self.confirm_entry.focus())
        self.confirm_entry.bind("<Return>", lambda e: self._do_setup())

        self.error_label = ctk.CTkLabel(self.content_frame, text="", font=("Segoe UI", 12), text_color="#d32f2f")
        self.error_label.pack(pady=(0, 15))

        inst_frame = ctk.CTkFrame(self.content_frame, fg_color="#e8f5e9", corner_radius=10)
        inst_frame.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(inst_frame, text="📋 After Setup:", font=("Segoe UI", 12, "bold"), text_color="#2e7d32").pack(anchor="w", padx=20, pady=(15, 8))
        ctk.CTkLabel(inst_frame, text="• Use 'User Access Controls' to add other users\n• Share the config folder with authorized users", font=("Segoe UI", 11), text_color="#1b5e20", justify="left").pack(anchor="w", padx=30, pady=(0, 15))

        button_frame = ctk.CTkFrame(self, fg_color="#f0f0f0", corner_radius=0, height=80)
        button_frame.pack(fill="x", side="bottom")
        button_frame.pack_propagate(False)

        self.submit_btn = ctk.CTkButton(button_frame, text="✓  Complete Setup", font=("Segoe UI", 16, "bold"), fg_color="#198754", hover_color="#157347", width=350, height=55, corner_radius=12, command=self._do_setup)
        self.submit_btn.pack(expand=True)

    def _do_setup(self):
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        self.error_label.configure(text="")

        if not password:
            self.error_label.configure(text="⚠️ Please enter a password")
            self.password_entry.focus()
            return

        if len(password) < 6:
            self.error_label.configure(text="⚠️ Password must be at least 6 characters")
            self.password_entry.focus()
            return

        if not confirm:
            self.error_label.configure(text="⚠️ Please confirm your password")
            self.confirm_entry.focus()
            return

        if password != confirm:
            self.error_label.configure(text="⚠️ Passwords do not match")
            self.confirm_entry.delete(0, "end")
            self.confirm_entry.focus()
            return

        self.submit_btn.configure(state="disabled", text="Setting up...")

        success, msg = self.auth_manager.setup_first_admin(password)

        if success:
            self.setup_complete = True
            messagebox.showinfo("Setup Complete", f"✅ Administrator account created!\n\nUsername: {self.auth_manager.current_user}\nRole: Primary Administrator\n\nYou can add other users via:\n'User Access Controls' button")
            self.destroy()
        else:
            self.submit_btn.configure(state="normal", text="✓  Complete Setup")
            self.error_label.configure(text=f"❌ {msg}")

    def _on_close(self):
        if not self.setup_complete:
            if messagebox.askyesno("Exit Setup", "Setup is not complete. Exit application?"):
                self.setup_complete = False
                self.destroy()
        else:
            self.destroy()


# ================= ACCESS DENIED DIALOG =================
class AccessDeniedDialog(ctk.CTkToplevel):
    """Dialog shown when user is not authorized."""

    def __init__(self, parent, auth_manager: WorkDocsUserAuthManager):
        super().__init__(parent)
        self.auth_manager = auth_manager

        self.title("Access Denied")
        self.geometry("500x350")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 350) // 2
        self.geometry(f"500x350+{x}+{y}")

        self._create_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_widgets(self):
        header = ctk.CTkFrame(self, fg_color="#dc3545", corner_radius=0, height=90)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🚫 ACCESS DENIED", font=("Segoe UI", 28, "bold"), text_color="white").pack(expand=True)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        ctk.CTkLabel(content, text="You don't have access to this application.", font=("Segoe UI", 16, "bold"), text_color="#333").pack(pady=(20, 30))

        contact_frame = ctk.CTkFrame(content, fg_color="#f8d7da", corner_radius=10)
        contact_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(contact_frame, text="Please contact the administrator:", font=("Segoe UI", 13), text_color="#721c24").pack(pady=(20, 10))
        ctk.CTkLabel(contact_frame, text=f"📧 {ADMIN_EMAIL}", font=("Segoe UI", 18, "bold"), text_color="#0d6efd").pack(pady=(0, 20))

        btn_frame = ctk.CTkFrame(self, fg_color="#f0f0f0", corner_radius=0, height=70)
        btn_frame.pack(fill="x", side="bottom")
        btn_frame.pack_propagate(False)

        ctk.CTkButton(btn_frame, text="OK", font=("Segoe UI", 14, "bold"), fg_color="#6c757d", hover_color="#5a6268", width=150, height=45, corner_radius=10, command=self._on_close).pack(expand=True)

    def _on_close(self):
        self.destroy()


# ================= ADMIN PASSWORD DIALOG =================
class AdminPasswordDialog(ctk.CTkToplevel):
    """Dialog for admin password verification."""

    def __init__(self, parent, auth_manager: WorkDocsUserAuthManager):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.verified = False

        self.title("Admin Authentication")
        self.geometry("500x380")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 380) // 2
        self.geometry(f"500x380+{x}+{y}")

        self._create_widgets()

    def _create_widgets(self):
        header = ctk.CTkFrame(self, fg_color="#1565c0", corner_radius=0, height=70)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🔐 Admin Authentication", font=("Segoe UI", 20, "bold"), text_color="white").pack(expand=True)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=40, pady=30)

        ctk.CTkLabel(content, text="Enter admin password to continue:", font=("Segoe UI", 14)).pack(pady=(15, 20))

        self.password_entry = ctk.CTkEntry(content, width=380, height=50, show="●", placeholder_text="Admin password", font=("Segoe UI", 14))
        self.password_entry.pack(pady=10)
        self.password_entry.bind("<Return>", lambda e: self._verify())
        self.password_entry.focus()

        self.error_label = ctk.CTkLabel(content, text="", text_color="#dc3545", font=("Segoe UI", 12))
        self.error_label.pack(pady=15)

        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=20)

        ctk.CTkButton(btn_frame, text="Login", width=150, height=50, font=("Segoe UI", 14, "bold"), fg_color="#198754", hover_color="#157347", corner_radius=10, command=self._verify).pack(side="left", padx=15)
        ctk.CTkButton(btn_frame, text="Cancel", width=150, height=50, font=("Segoe UI", 14), fg_color="#6c757d", hover_color="#5a6268", corner_radius=10, command=self.destroy).pack(side="left", padx=15)

    def _verify(self):
        password = self.password_entry.get()

        if self.auth_manager.verify_admin_password(password):
            self.verified = True
            self.destroy()
        else:
            self.error_label.configure(text="❌ Incorrect password")
            self.password_entry.delete(0, "end")
            self.password_entry.focus()


# ================= USER ACCESS CONTROLS DIALOG =================
class UserAccessControlsDialog(ctk.CTkToplevel):
    """Combined User Access Controls dialog."""

    def __init__(self, parent, auth_manager: WorkDocsUserAuthManager, storage: TransparentSecureStorage):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.storage = storage

        self.title("User Access Controls")
        self.geometry("1000x850")
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 1000) // 2
        y = (self.winfo_screenheight() - 850) // 2
        self.geometry(f"1000x850+{x}+{y}")

        self._create_widgets()
        self._load_data()

    def _create_widgets(self):
        header = ctk.CTkFrame(self, fg_color="#2c3e50", corner_radius=0, height=90)
        header.pack(fill="x")
        header.pack_propagate(False)

        header_content = ctk.CTkFrame(header, fg_color="transparent")
        header_content.pack(fill="x", expand=True, padx=30)

        ctk.CTkLabel(header_content, text="🔐 User Access Controls", font=("Segoe UI", 26, "bold"), text_color="white").pack(side="left", pady=30)

        config_info = self.auth_manager.get_config_info()
        status_color = "#27ae60" if config_info["is_admin"] else "#3498db"
        status_text = "⭐ Administrator" if config_info["is_admin"] else "👤 User"

        status_badge = ctk.CTkFrame(header_content, fg_color=status_color, corner_radius=15)
        status_badge.pack(side="right", pady=30)
        ctk.CTkLabel(status_badge, text=status_text, font=("Segoe UI", 12, "bold"), text_color="white").pack(padx=18, pady=8)

        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=15)

        left_col = ctk.CTkFrame(main_frame, fg_color="transparent", width=480)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        user_card = ctk.CTkFrame(left_col, fg_color="#ecf0f1", corner_radius=12)
        user_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(user_card, text="👤 Current User", font=("Segoe UI", 15, "bold"), text_color="#2c3e50").pack(anchor="w", padx=18, pady=(15, 8))

        user_info_grid = ctk.CTkFrame(user_card, fg_color="transparent")
        user_info_grid.pack(fill="x", padx=18, pady=(0, 15))

        info_items = [
            ("Username:", config_info["current_user"]),
            ("Role:", "Primary Admin" if config_info.get("is_primary_admin") else ("Administrator" if config_info["is_admin"] else "Standard User")),
            ("Config Source:", config_info["config_source"]),
        ]

        for label, value in info_items:
            row = ctk.CTkFrame(user_info_grid, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, font=("Segoe UI", 11), text_color="#7f8c8d", width=110, anchor="e").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Segoe UI", 11, "bold"), text_color="#2c3e50").pack(side="left", padx=12)

        users_card = ctk.CTkFrame(left_col, fg_color="#ffffff", corner_radius=12)
        users_card.pack(fill="both", expand=True, pady=(0, 12))

        users_header = ctk.CTkFrame(users_card, fg_color="#3498db", corner_radius=0)
        users_header.pack(fill="x")

        ctk.CTkLabel(users_header, text="👥 Authorized Users", font=("Segoe UI", 14, "bold"), text_color="white").pack(side="left", padx=18, pady=12)

        self.user_count_label = ctk.CTkLabel(users_header, text="0 users", font=("Segoe UI", 11), text_color="#bdc3c7")
        self.user_count_label.pack(side="right", padx=18, pady=12)

        self.users_list = ctk.CTkScrollableFrame(users_card, fg_color="transparent", height=250)
        self.users_list.pack(fill="both", expand=True, padx=12, pady=12)

        if config_info["can_write"]:
            add_card = ctk.CTkFrame(left_col, fg_color="#e8f6e9", corner_radius=12)
            add_card.pack(fill="x")

            ctk.CTkLabel(add_card, text="➕ Add New User", font=("Segoe UI", 14, "bold"), text_color="#27ae60").pack(anchor="w", padx=18, pady=(15, 12))

            add_form = ctk.CTkFrame(add_card, fg_color="transparent")
            add_form.pack(fill="x", padx=18, pady=(0, 15))

            row1 = ctk.CTkFrame(add_form, fg_color="transparent")
            row1.pack(fill="x", pady=5)

            ctk.CTkLabel(row1, text="Username:", font=("Segoe UI", 11), width=85).pack(side="left")
            self.username_entry = ctk.CTkEntry(row1, width=160, height=38, placeholder_text="Windows username", font=("Segoe UI", 11))
            self.username_entry.pack(side="left", padx=8)
            ctk.CTkLabel(row1, text="Full Name:", font=("Segoe UI", 11), width=75).pack(side="left", padx=(12, 0))
            self.fullname_entry = ctk.CTkEntry(row1, width=140, height=38, placeholder_text="Display name", font=("Segoe UI", 11))
            self.fullname_entry.pack(side="left", padx=8)

            row2 = ctk.CTkFrame(add_form, fg_color="transparent")
            row2.pack(fill="x", pady=(10, 0))

            ctk.CTkButton(row2, text="➕ Add User", width=140, height=40, font=("Segoe UI", 12, "bold"), fg_color="#27ae60", hover_color="#1e8449", command=self._add_user).pack(side="left")

        right_col = ctk.CTkFrame(main_frame, fg_color="transparent", width=480)
        right_col.pack(side="right", fill="both", expand=True, padx=(10, 0))

        settings_card = ctk.CTkFrame(right_col, fg_color="#ffffff", corner_radius=12)
        settings_card.pack(fill="x", pady=(0, 12))

        settings_header = ctk.CTkFrame(settings_card, fg_color="#9b59b6", corner_radius=0)
        settings_header.pack(fill="x")

        ctk.CTkLabel(settings_header, text="⚙️ Security Settings", font=("Segoe UI", 14, "bold"), text_color="white").pack(side="left", padx=18, pady=12)

        settings_content = ctk.CTkFrame(settings_card, fg_color="transparent")
        settings_content.pack(fill="x", padx=18, pady=15)

        stats = self.storage.get_stats()
        efs_color = "#27ae60" if stats["efs_available"] else "#e67e22"
        efs_text = "✅ EFS Encryption Active" if stats["efs_available"] else "⚠️ EFS Not Available"

        efs_frame = ctk.CTkFrame(settings_content, fg_color="#f8f9fa", corner_radius=8)
        efs_frame.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(efs_frame, text=efs_text, font=("Segoe UI", 12, "bold"), text_color=efs_color).pack(pady=10)

        ret_frame = ctk.CTkFrame(settings_content, fg_color="transparent")
        ret_frame.pack(fill="x", pady=8)

        ctk.CTkLabel(ret_frame, text="📅 Data Retention (days):", font=("Segoe UI", 12)).pack(side="left")
        self.retention_entry = ctk.CTkEntry(ret_frame, width=80, height=38, font=("Segoe UI", 12))
        self.retention_entry.pack(side="left", padx=12)
        self.retention_entry.insert(0, str(self.storage.config.get("retention_days", DEFAULT_RETENTION_DAYS)))

        self.auto_delete_var = ctk.BooleanVar(value=self.storage.config.get("auto_delete_enabled", True))
        ctk.CTkCheckBox(settings_content, text="Auto-delete expired data", variable=self.auto_delete_var, font=("Segoe UI", 12)).pack(anchor="w", pady=5)

        self.audit_var = ctk.BooleanVar(value=self.storage.config.get("audit_logging_enabled", True))
        ctk.CTkCheckBox(settings_content, text="Enable audit logging", variable=self.audit_var, font=("Segoe UI", 12)).pack(anchor="w", pady=5)

        ctk.CTkButton(settings_content, text="💾 Save Settings", width=150, height=38, font=("Segoe UI", 12), fg_color="#9b59b6", hover_color="#8e44ad", command=self._save_settings).pack(anchor="w", pady=(12, 0))

        stats_card = ctk.CTkFrame(right_col, fg_color="#ffffff", corner_radius=12)
        stats_card.pack(fill="x", pady=(0, 12))

        stats_header = ctk.CTkFrame(stats_card, fg_color="#e67e22", corner_radius=0)
        stats_header.pack(fill="x")

        ctk.CTkLabel(stats_header, text="📊 Extraction Statistics", font=("Segoe UI", 14, "bold"), text_color="white").pack(side="left", padx=18, pady=12)

        stats_content = ctk.CTkFrame(stats_card, fg_color="transparent")
        stats_content.pack(fill="x", padx=18, pady=15)

        stats_grid = ctk.CTkFrame(stats_content, fg_color="#f8f9fa", corner_radius=8)
        stats_grid.pack(fill="x")

        stat_items = [
            ("📊 Total Extractions:", str(stats["total_extractions"])),
            ("📄 Total Records:", str(stats["total_records"])),
            ("🔒 EFS Status:", "Active" if stats["efs_available"] else "Unavailable"),
        ]

        for label, value in stat_items:
            stat_row = ctk.CTkFrame(stats_grid, fg_color="transparent")
            stat_row.pack(fill="x", padx=12, pady=5)
            ctk.CTkLabel(stat_row, text=label, font=("Segoe UI", 11), text_color="#7f8c8d", width=130, anchor="w").pack(side="left")
            ctk.CTkLabel(stat_row, text=value, font=("Segoe UI", 12, "bold"), text_color="#2c3e50").pack(side="left")

        log_card = ctk.CTkFrame(right_col, fg_color="#ffffff", corner_radius=12)
        log_card.pack(fill="both", expand=True)

        log_header = ctk.CTkFrame(log_card, fg_color="#34495e", corner_radius=0)
        log_header.pack(fill="x")

        ctk.CTkLabel(log_header, text="📋 Recent Access Log", font=("Segoe UI", 14, "bold"), text_color="white").pack(side="left", padx=18, pady=12)

        self.log_list = ctk.CTkScrollableFrame(log_card, fg_color="transparent", height=180)
        self.log_list.pack(fill="both", expand=True, padx=12, pady=12)

        btn_bar = ctk.CTkFrame(self, fg_color="#ecf0f1", corner_radius=0, height=80)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        btn_inner = ctk.CTkFrame(btn_bar, fg_color="transparent")
        btn_inner.pack(expand=True, fill="x", padx=25)

        ctk.CTkButton(btn_inner, text="🔄 Refresh", width=120, height=45, font=("Segoe UI", 12), fg_color="#3498db", hover_color="#2980b9", command=self._load_data).pack(side="left", pady=18)

        if config_info["can_write"]:
            ctk.CTkButton(btn_inner, text="🔑 Change Password", width=170, height=45, font=("Segoe UI", 12), fg_color="#e67e22", hover_color="#d35400", command=self._change_password).pack(side="left", padx=12, pady=18)

        ctk.CTkButton(btn_inner, text="📋 View Audit Log File", width=170, height=45, font=("Segoe UI", 12), fg_color="#34495e", hover_color="#2c3e50", command=self._view_audit_file).pack(side="left", padx=12, pady=18)

        ctk.CTkButton(btn_inner, text="Close", width=120, height=45, font=("Segoe UI", 12), fg_color="#95a5a6", hover_color="#7f8c8d", command=self.destroy).pack(side="right", pady=18)

    def _load_data(self):
        for widget in self.users_list.winfo_children():
            widget.destroy()
        for widget in self.log_list.winfo_children():
            widget.destroy()

        self.auth_manager.load_config()

        users = self.auth_manager.get_authorized_users()
        self.user_count_label.configure(text=f"{len(users)} user(s)")

        if not users:
            ctk.CTkLabel(self.users_list, text="No users configured", text_color="#95a5a6", font=("Segoe UI", 12)).pack(pady=35)
        else:
            for user in users:
                self._create_user_row(user)

        logs = self.auth_manager.get_access_log()[-15:]
        logs.reverse()

        if not logs:
            ctk.CTkLabel(self.log_list, text="No access log entries", text_color="#95a5a6", font=("Segoe UI", 12)).pack(pady=25)
        else:
            for log in logs:
                self._create_log_row(log)

    def _create_user_row(self, user: Dict):
        is_admin = user.get("is_admin", False)
        is_current = user.get("username", "").lower() == self.auth_manager.current_user.lower()
        is_primary = user.get("username", "").lower() == ADMIN_USERNAME.lower()

        bg_color = "#fff9e6" if is_admin else "#f8f9fa"
        if is_current:
            bg_color = "#e8f4fd"

        row = ctk.CTkFrame(self.users_list, fg_color=bg_color, corner_radius=8)
        row.pack(fill="x", pady=4, padx=3)

        icon = "⭐" if is_primary else ("🔑" if is_admin else "👤")
        name_color = "#e65100" if is_primary else ("#e67e22" if is_admin else "#2c3e50")

        left_frame = ctk.CTkFrame(row, fg_color="transparent")
        left_frame.pack(side="left", fill="x", expand=True, padx=12, pady=10)

        name_row = ctk.CTkFrame(left_frame, fg_color="transparent")
        name_row.pack(fill="x")

        ctk.CTkLabel(name_row, text=f"{icon} {user.get('username', 'unknown')}", font=("Segoe UI", 12, "bold"), text_color=name_color).pack(side="left")

        if is_current:
            ctk.CTkLabel(name_row, text="(You)", font=("Segoe UI", 10), text_color="#3498db").pack(side="left", padx=6)

        if is_primary:
            role_text = "Primary Admin"
            role_color = "#e65100"
        elif is_admin:
            role_text = "Admin"
            role_color = "#e67e22"
        else:
            role_text = "User"
            role_color = "#95a5a6"

        role_badge = ctk.CTkFrame(name_row, fg_color=role_color, corner_radius=10)
        role_badge.pack(side="left", padx=12)
        ctk.CTkLabel(role_badge, text=role_text, font=("Segoe UI", 9), text_color="white").pack(padx=10, pady=3)

        details_row = ctk.CTkFrame(left_frame, fg_color="transparent")
        details_row.pack(fill="x")

        ctk.CTkLabel(details_row, text=f"{user.get('full_name', '')} • Added: {user.get('added_on', '')[:10]}", font=("Segoe UI", 10), text_color="#7f8c8d").pack(side="left")

        config_info = self.auth_manager.get_config_info()
        if config_info["can_write"] and not is_current and not is_primary:
            ctk.CTkButton(row, text="🗑️", width=40, height=35, font=("Segoe UI", 12), fg_color="#e74c3c", hover_color="#c0392b", command=lambda u=user.get("username", ""): self._remove_user(u)).pack(side="right", padx=12, pady=10)

    def _create_log_row(self, log: Dict):
        row = ctk.CTkFrame(self.log_list, fg_color="transparent")
        row.pack(fill="x", pady=2)

        timestamp = log.get("timestamp", "")[:16].replace("T", " ")
        event = log.get("event", "")
        user = log.get("user", "").split("\\")[-1]

        if "GRANTED" in event:
            color = "#27ae60"
            icon = "✅"
        elif "DENIED" in event:
            color = "#e74c3c"
            icon = "❌"
        elif "ADDED" in event:
            color = "#3498db"
            icon = "➕"
        elif "REMOVED" in event:
            color = "#e67e22"
            icon = "➖"
        elif "PASSWORD" in event:
            color = "#9b59b6"
            icon = "🔑"
        else:
            color = "#7f8c8d"
            icon = "📋"

        ctk.CTkLabel(row, text=timestamp, font=("Segoe UI", 10), text_color="#95a5a6", width=120).pack(side="left")
        ctk.CTkLabel(row, text=f"{icon} {user}", font=("Segoe UI", 10), text_color=color, width=110).pack(side="left")
        ctk.CTkLabel(row, text=event, font=("Segoe UI", 10), text_color=color).pack(side="left", padx=8)

    def _add_user(self):
        username = self.username_entry.get().strip()
        fullname = self.fullname_entry.get().strip()

        if not username:
            messagebox.showwarning("Error", "Please enter a Windows username")
            return

        success, msg = self.auth_manager.add_user(username, fullname)

        if success:
            messagebox.showinfo("Success", msg)
            self.username_entry.delete(0, "end")
            self.fullname_entry.delete(0, "end")
            self._load_data()
        else:
            messagebox.showerror("Error", msg)

    def _remove_user(self, username: str):
        if not messagebox.askyesno("Confirm Remove", f"Remove user '{username}'?\n\nThey will no longer be able to use the application."):
            return

        success, msg = self.auth_manager.remove_user(username)

        if success:
            messagebox.showinfo("Success", msg)
            self._load_data()
        else:
            messagebox.showerror("Error", msg)

    def _save_settings(self):
        try:
            retention = int(self.retention_entry.get())
            if retention < 1:
                raise ValueError("Must be at least 1 day")

            self.storage.config["retention_days"] = retention
            self.storage.config["auto_delete_enabled"] = self.auto_delete_var.get()
            self.storage.config["audit_logging_enabled"] = self.audit_var.get()
            self.storage.save_config()

            messagebox.showinfo("Success", "✅ Settings saved successfully!")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def _change_password(self):
        dialog = ChangePasswordDialog(self, self.auth_manager)
        dialog.wait_window()

    def _view_audit_file(self):
        if os.path.exists(self.storage.audit_log_path):
            os.startfile(self.storage.audit_log_path)
        else:
            messagebox.showinfo("Info", "No audit log file exists yet.")


# ================= CHANGE PASSWORD DIALOG =================
class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, auth_manager: WorkDocsUserAuthManager):
        super().__init__(parent)
        self.auth_manager = auth_manager

        self.title("Change Admin Password")
        self.geometry("500x450")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 450) // 2
        self.geometry(f"500x450+{x}+{y}")

        self._create_widgets()

    def _create_widgets(self):
        header = ctk.CTkFrame(self, fg_color="#e67e22", corner_radius=0, height=70)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🔑 Change Admin Password", font=("Segoe UI", 18, "bold"), text_color="white").pack(expand=True)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=40, pady=25)

        ctk.CTkLabel(content, text="Current Password:", font=("Segoe UI", 12), anchor="w").pack(fill="x", pady=(10, 5))
        self.current_entry = ctk.CTkEntry(content, width=380, height=45, show="●", font=("Segoe UI", 13))
        self.current_entry.pack(pady=(0, 15))

        ctk.CTkLabel(content, text="New Password:", font=("Segoe UI", 12), anchor="w").pack(fill="x", pady=(5, 5))
        self.new_entry = ctk.CTkEntry(content, width=380, height=45, show="●", font=("Segoe UI", 13))
        self.new_entry.pack(pady=(0, 15))

        ctk.CTkLabel(content, text="Confirm New Password:", font=("Segoe UI", 12), anchor="w").pack(fill="x", pady=(5, 5))
        self.confirm_entry = ctk.CTkEntry(content, width=380, height=45, show="●", font=("Segoe UI", 13))
        self.confirm_entry.pack(pady=(0, 15))

        self.error_label = ctk.CTkLabel(content, text="", text_color="#e74c3c", font=("Segoe UI", 11))
        self.error_label.pack(pady=8)

        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=15)

        ctk.CTkButton(btn_frame, text="Change Password", width=170, height=48, font=("Segoe UI", 13, "bold"), fg_color="#27ae60", hover_color="#1e8449", corner_radius=10, command=self._change).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cancel", width=120, height=48, font=("Segoe UI", 13), fg_color="#95a5a6", hover_color="#7f8c8d", corner_radius=10, command=self.destroy).pack(side="left", padx=10)

        self.current_entry.focus()

    def _change(self):
        current = self.current_entry.get()
        new = self.new_entry.get()
        confirm = self.confirm_entry.get()

        if not current:
            self.error_label.configure(text="⚠️ Enter current password")
            return

        if len(new) < 6:
            self.error_label.configure(text="⚠️ New password must be at least 6 characters")
            return

        if new != confirm:
            self.error_label.configure(text="⚠️ New passwords do not match")
            return

        success, msg = self.auth_manager.change_admin_password(current, new)

        if success:
            messagebox.showinfo("Success", "✅ Password changed successfully!")
            self.destroy()
        else:
            self.error_label.configure(text=f"❌ {msg}")


# ================= GUI =================
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


def start_gui():
    global secure_storage, user_auth

    user_auth = WorkDocsUserAuthManager()

    temp_root = ctk.CTk()
    temp_root.withdraw()

    if user_auth.is_primary_admin():
        if user_auth.is_first_time_setup():
            if not user_auth.can_write:
                messagebox.showerror(
                    "Setup Error",
                    f"Cannot create configuration file.\n\n"
                    f"Expected location:\n{user_auth.local_config_path}\n\n"
                    f"Make sure:\n"
                    f"1. WorkDocs Drive (W:) is installed and synced\n"
                    f"2. You have write access to 'My Documents'\n\n"
                    f"Please try again after fixing the issue."
                )
                temp_root.destroy()
                return

            setup_dialog = FirstTimeSetupDialog(temp_root, user_auth)
            setup_dialog.wait_window()

            if not setup_dialog.setup_complete:
                temp_root.destroy()
                return
        else:
            user_auth.load_config()
            user_auth.is_admin = True
            user_auth._log_access("ACCESS_GRANTED", f"Admin user {user_auth.current_user} authorized")
    else:
        if user_auth.is_first_time_setup():
            denied_dialog = AccessDeniedDialog(temp_root, user_auth)
            denied_dialog.wait_window()
            temp_root.destroy()
            return

        authorized, message = user_auth.check_authorization()

        if not authorized:
            denied_dialog = AccessDeniedDialog(temp_root, user_auth)
            denied_dialog.wait_window()
            temp_root.destroy()
            return

    temp_root.destroy()

    secure_storage = TransparentSecureStorage()

    if not is_chrome_running():
        startup_clear_success, startup_clear_msg = force_delete_chrome_profile()
    else:
        startup_clear_success, startup_clear_msg = False, "Chrome running - will clear when closed"

    app = ctk.CTk()
    app.geometry("980x700")
    app.title("Egypt eInvoice Extractor (Secure)")

    app_closing = [False]

    def on_closing():
        app_closing[0] = True

        try:
            if is_chrome_running():
                kill_chrome_processes()
                time.sleep(3)
            force_delete_chrome_profile()
            if secure_storage:
                secure_storage._audit_log("APP_EXIT", "Chrome profile deleted on exit")
        except Exception as e:
            if secure_storage:
                secure_storage._audit_log("APP_EXIT_ERROR", f"Cleanup error: {e}")

        try:
            app.quit()
        except Exception:
            pass

        try:
            app.destroy()
        except Exception:
            pass

    app.protocol("WM_DELETE_WINDOW", on_closing)

    try:
        app.wm_iconphoto(True, ImageTk.PhotoImage(Image.open(resource_path("pyramid_app_icon.png"))))
    except:
        pass

    try:
        banner = ctk.CTkImage(Image.open(resource_path("header_banner.png")), size=(980, 150))
        ctk.CTkLabel(app, image=banner, text="").pack(fill="x")
    except:
        header_frame = ctk.CTkFrame(app, height=100, fg_color="#1f6feb")
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text="Egypt eInvoice Extractor", font=("Segoe UI", 24, "bold"), text_color="white").pack(pady=30)

    user_info_frame = ctk.CTkFrame(app, fg_color="#e3f2fd")
    user_info_frame.pack(fill="x", padx=20, pady=(5, 0))

    user_icon = "⭐" if user_auth.is_primary_admin() else ("🔑" if user_auth.is_admin else "👤")
    user_role = "Primary Admin" if user_auth.is_primary_admin() else ("Admin" if user_auth.is_admin else "User")
    ctk.CTkLabel(user_info_frame, text=f"{user_icon} {user_auth.current_user} ({user_role}) | 📁 Config: {user_auth.config_source}", font=("Segoe UI", 10), text_color="#1565c0").pack(side="left", padx=15, pady=5)

    stats = secure_storage.get_stats()
    security_frame = ctk.CTkFrame(app, fg_color="#e8f5e9" if stats["efs_available"] else "#fff3cd")
    security_frame.pack(fill="x", padx=20, pady=5)

    efs_icon = "🔒" if stats["efs_available"] else "⚠️"
    efs_text = "EFS Active" if stats["efs_available"] else "NTFS Protected"

    security_label = ctk.CTkLabel(
        security_frame,
        text=f"{efs_icon} {efs_text} | 📊 {stats['total_extractions']} extractions | 📄 {stats['total_records']} records | 📅 {stats['retention_days']}d retention",
        font=("Segoe UI", 11),
        text_color="#2e7d32" if stats["efs_available"] else "#856404"
    )
    security_label.pack(side="left", padx=15, pady=8)

    def update_security_bar():
        if app_closing[0]:
            return
        try:
            stats = secure_storage.get_stats()
            efs_icon = "🔒" if stats["efs_available"] else "⚠️"
            efs_text = "EFS Active" if stats["efs_available"] else "NTFS Protected"
            security_label.configure(
                text=f"{efs_icon} {efs_text} | 📊 {stats['total_extractions']} extractions | 📄 {stats['total_records']} records | 📅 {stats['retention_days']}d retention"
            )
        except Exception:
            pass

    status_var = ctk.StringVar(value="Ready")
    ctk.CTkLabel(app, textvariable=status_var, font=("Segoe UI", 12, "bold")).pack(pady=6)

    progress = ctk.CTkProgressBar(app, width=880)
    progress.set(0)
    progress.pack(pady=6)

    time_lbl = ctk.CTkLabel(app, text="Elapsed: 00:00 | ETA: N/A")
    time_lbl.pack()

    btn_frame = ctk.CTkFrame(app)
    btn_frame.pack(pady=10)

    output_dir_holder = {"path": None}

    def start():
        cancel_event.clear()
        pause_event.set()

        if is_chrome_running():
            result = messagebox.askyesno(
                "Chrome Running",
                "Chrome is currently running. It must be closed to proceed.\n\n"
                "Do you want to close Chrome now?\n\n"
                "(Make sure you've already logged into ETA portal)"
            )
            if result:
                ui_log("🔄 Closing Chrome processes...")
                kill_chrome_processes()
                ui_log("✅ Chrome closed")
            else:
                messagebox.showwarning("Chrome Must Be Closed", "Please close Chrome manually and try again.")
                return

        excel = filedialog.askopenfilename(filetypes=[("Excel Files", "*.xlsx")])
        if not excel:
            return

        # FIX FOR ISSUE 2: Generate output path in secure storage with timestamp
        output = secure_storage.get_output_filepath(excel)
        output_dir_holder["path"] = secure_storage.secure_folder

        def worker():
            try:
                status_var.set("Checking ETA session...")
                ui_log("=" * 50)
                ui_log("🚀 Starting extraction process...")
                ui_log(f"📂 Input file: {excel}")
                ui_log(f"📁 Output will be saved to:")
                ui_log(f"   {output}")

                try:
                    check_eta_session()
                except RuntimeError as e:
                    messagebox.showerror("Authentication Required", str(e))
                    status_var.set("Authentication Required ❌")
                    return

                status_var.set("Extracting...")

                run_extraction(
                    excel, output,
                    lambda p: progress.set(p),
                    lambda e, eta: time_lbl.configure(
                        text=f"Elapsed: {int(e // 60):02}:{int(e % 60):02} | ETA: {int(eta // 60):02}:{int(eta % 60):02}"
                    )
                )

                status_var.set("Completed ✅")
                update_security_bar()

                messagebox.showinfo(
                    "Done",
                    f"Extraction completed successfully!\n\n"
                    f"📁 Output saved to:\n{output}\n\n"
                    f"Click 'Open Output Folder' to view the file."
                )

            except Exception as ex:
                ui_log(f"❌ Error: {str(ex)}")
                messagebox.showerror("Error", str(ex))
                status_var.set("Error ❌")

        threading.Thread(target=worker, daemon=True).start()

    def open_output():
        """Open the secure storage folder where outputs are saved."""
        if secure_storage:
            secure_storage.open_folder()
        elif output_dir_holder["path"]:
            os.startfile(output_dir_holder["path"])

    def toggle_pause():
        if pause_event.is_set():
            pause_event.clear()
            status_var.set("Paused ⏸")
            ui_log("⏸ Extraction paused")
        else:
            pause_event.set()
            status_var.set("Extracting...")
            ui_log("▶ Extraction resumed")

    def open_access_controls():
        if not user_auth.is_admin and not user_auth.is_primary_admin():
            messagebox.showwarning(
                "Access Denied",
                f"Only administrators can access User Access Controls.\n\n"
                f"Please contact the administrator:\n"
                f"📧 {ADMIN_EMAIL}"
            )
            return

        password_dialog = AdminPasswordDialog(app, user_auth)
        password_dialog.wait_window()

        if password_dialog.verified:
            dialog = UserAccessControlsDialog(app, user_auth, secure_storage)
            dialog.wait_window()
            update_security_bar()

    def cancel():
        cancel_event.set()
        status_var.set("Cancelling...")

    def open_eta_login():
        if is_chrome_running():
            result = messagebox.askyesno(
                "Chrome Running",
                "Chrome is currently running.\n\n"
                "Do you want to CLOSE Chrome?\n\n"
                "⚠️ This is required to clear all login data."
            )
            if result:
                ui_log("🔄 Closing Chrome...")
                kill_chrome_processes()
                time.sleep(3)
            else:
                return

        ui_log("🗑️ DELETING entire Chrome profile...")
        ui_log("   This removes ALL:")
        ui_log("   ├── Cookies")
        ui_log("   ├── Saved passwords")
        ui_log("   ├── Browsing history")
        ui_log("   ├── Cache")
        ui_log("   └── All other data")

        success, msg = force_delete_chrome_profile()
        ui_log(f"   ✅ {msg}")

        if secure_storage:
            secure_storage._audit_log("LOGIN_PREP", f"Profile deleted: {msg}")

        profile_dir = get_profile_dir()

        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]

        chrome_path = None
        for path in chrome_paths:
            if os.path.exists(path):
                chrome_path = path
                break

        if not chrome_path:
            messagebox.showerror("Error", "Chrome not found. Please install Google Chrome.")
            return

        try:
            chrome_args = [
                chrome_path,
                f"--user-data-dir={profile_dir}",
                "--disable-save-password-bubble",
                "--disable-features=PasswordManager",
                "--disable-features=AutofillServerCommunication",
                "--disable-translate",
                "--no-first-run",
                "--no-default-browser-check",
                "--password-store=basic",
                "--disable-sync",
                "--disable-background-networking",
                ETA_BASE_URL
            ]

            subprocess.Popen(chrome_args)
            ui_log("🌐 Opened FRESH Chrome browser for ETA portal login")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Chrome: {e}")

    # Main buttons
    ctk.CTkButton(btn_frame, text="🌐 Login to ETA", fg_color="#17a2b8", command=open_eta_login).pack(side="left", padx=6)
    ctk.CTkButton(btn_frame, text="▶ Start Extraction", fg_color="#1f6feb", command=start).pack(side="left", padx=6)
    ctk.CTkButton(btn_frame, text="⏸ Pause / Resume", fg_color="#f0ad4e", command=toggle_pause).pack(side="left", padx=6)
    ctk.CTkButton(btn_frame, text="📂 Open Output Folder", fg_color="#198754", command=open_output).pack(side="left", padx=6)
    ctk.CTkButton(btn_frame, text="🔐 User Access Controls", fg_color="#2c3e50", command=open_access_controls).pack(side="left", padx=6)
    ctk.CTkButton(btn_frame, text="❌ Cancel", fg_color="#d9534f", command=cancel).pack(side="left", padx=6)

    log_frame = ctk.CTkFrame(app)
    log_frame.pack(fill="both", expand=True, padx=20, pady=10)

    try:
        bg = ctk.CTkImage(Image.open(resource_path("pyramid_bg.png")), size=(900, 260))
        ctk.CTkLabel(log_frame, image=bg, text="").place(relx=0.5, rely=0.5, anchor="center")
    except:
        pass

    log_box = ctk.CTkTextbox(log_frame, height=260)
    log_box.pack(fill="both", expand=True)

    def pump_logs():
        if app_closing[0]:
            return

        try:
            while True:
                try:
                    msg = log_queue.get_nowait()
                    if not app_closing[0]:
                        log_box.insert("end", msg + "\n")
                        log_box.see("end")
                except queue.Empty:
                    break
        except Exception:
            return

        if not app_closing[0]:
            try:
                app.after(100, pump_logs)
            except Exception:
                pass

    pump_logs()

    # Startup logs
    ui_log("🔒 Secure storage initialized")
    ui_log(f"📂 Storage Location: {secure_storage.secure_folder}")
    ui_log(f"🌐 Chrome profile: {secure_storage.chrome_profile_folder}")
    ui_log(f"📁 Config Location: {user_auth.local_config_path}")

    if secure_storage.efs_available:
        ui_log("✅ Windows EFS encryption is active")
        ui_log("   ├── Data storage: ENCRYPTED")
        ui_log("   └── Chrome profile: ENCRYPTED")
    else:
        ui_log("⚠️ Windows EFS not available (Windows Home edition?)")
        ui_log("   Files are still protected by NTFS permissions")

    ui_log("")
    ui_log("👤 User Authorization:")
    ui_log(f"   ├── User: {user_auth.current_user}")
    ui_log(f"   ├── Role: {'Primary Admin' if user_auth.is_primary_admin() else ('Administrator' if user_auth.is_admin else 'User')}")
    ui_log(f"   └── Config Source: {user_auth.config_source}")

    ui_log("")
    ui_log("🔐 Session security check...")
    if startup_clear_success:
        ui_log(f"   ✅ {startup_clear_msg}")
    else:
        ui_log(f"   ⚠️ {startup_clear_msg}")

    ui_log(f"📅 Data retention: {secure_storage.config['retention_days']} days")

    ui_log("")
    ui_log("=" * 50)
    ui_log("📋 HOW TO USE:")
    ui_log("   1. Click '🌐 Login to ETA' button")
    ui_log("   2. Complete ETA portal authentication (fresh session)")
    ui_log("   3. If asked to save password → Click NEVER")
    ui_log("   4. Close Chrome completely")
    ui_log("   5. Click '▶ Start Extraction'")
    ui_log("   6. Select your Excel file with UUIDs")
    ui_log("")
    ui_log("🔐 SECURITY FEATURES:")
    ui_log("   • Chrome profile DELETED before each login")
    ui_log("   • No cookies, passwords, or history saved")
    ui_log("   • Profile also deleted on app exit")
    ui_log("   • User access controlled via config file")
    ui_log("   • EFS encryption for secure storage")
    ui_log("   • NTFS permissions restrict folder access")
    ui_log("   • Audit logging enabled")
    ui_log("")
    ui_log("📁 OUTPUT LOCATION:")
    ui_log(f"   {secure_storage.secure_folder}")
    ui_log("   Files saved with date/time suffix")
    ui_log("=" * 50)
    ui_log("")

    app.mainloop()


if __name__ == "__main__":
    start_gui()