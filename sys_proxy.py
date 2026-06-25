import ctypes
from ctypes import Structure, Union, POINTER, byref, sizeof, create_unicode_buffer, c_wchar_p
from ctypes.wintypes import DWORD, LPWSTR, FILETIME
import winreg
import logging

logger = logging.getLogger("LibertyGSM.sys_proxy")

# WinINet Constants
INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3
INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39

# Option flag values
PROXY_TYPE_DIRECT = 1
PROXY_TYPE_PROXY = 2

# Registry Path
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Global backup variables
_backup_enable = 0
_backup_server = ""
_backup_override = ""
_has_backup = False

class INTERNET_PER_CONN_OPTION(Structure):
    class Value(Union):
        _fields_ = [('dwValue', DWORD), ('pszValue', LPWSTR), ('ftValue', FILETIME)]
    _fields_ = [('dwOption', DWORD), ('Value', Value)]

class INTERNET_PER_CONN_OPTION_LIST(Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('pszConnection', LPWSTR),
        ('dwOptionCount', DWORD),
        ('dwOptionError', DWORD),
        ('pOptions', POINTER(INTERNET_PER_CONN_OPTION)),
    ]

def backup_proxy_settings():
    """Reads and backs up the current system proxy settings from the Windows Registry."""
    global _backup_enable, _backup_server, _backup_override, _has_backup
    if _has_backup:
        return

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
            try:
                _backup_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                _backup_enable = 0

            try:
                _backup_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                _backup_server = ""

            try:
                _backup_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            except FileNotFoundError:
                _backup_override = ""

        _has_backup = True
        logger.info(f"Original proxy settings backed up: Enable={_backup_enable}, Server='{_backup_server}', Override='{_backup_override}'")
    except Exception as e:
        logger.error(f"Failed to backup system proxy settings: {e}")

def set_proxy(enable: bool, server: str = "127.0.0.1:10809", override: str = "localhost;127.0.0.1;<local>"):
    """Sets the system proxy settings in the Windows Registry and WinINet connections."""
    backup_proxy_settings()

    # 1. Update Registry for persistence
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE | winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            if override is not None:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
    except Exception as e:
        logger.warning(f"Could not write registry keys: {e}")

    # 2. Update via WinINet InternetSetOption (Forces active browsers to apply changes immediately)
    try:
        options = (INTERNET_PER_CONN_OPTION * 3)()
        
        # Flag option
        options[0].dwOption = INTERNET_PER_CONN_FLAGS
        # dwValue 3 represents PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY (use proxy for external, direct for local)
        # dwValue 1 represents PROXY_TYPE_DIRECT (no proxy)
        options[0].Value.dwValue = (PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY) if enable else PROXY_TYPE_DIRECT
        
        # Store pointers in local variables to prevent garbage collection
        server_ptr = c_wchar_p(server) if enable else None
        override_ptr = c_wchar_p(override) if (enable and override) else None
        
        # Server option
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER
        options[1].Value.pszValue = server_ptr
        
        # Bypass option
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS
        options[2].Value.pszValue = override_ptr

        conn_list = INTERNET_PER_CONN_OPTION_LIST()
        conn_list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST)
        conn_list.pszConnection = None  # None sets global/LAN connection proxy
        conn_list.dwOptionCount = 3
        conn_list.pOptions = options

        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        
        # Apply connection options
        success = internet_set_option(None, INTERNET_OPTION_PER_CONNECTION_OPTION, byref(conn_list), conn_list.dwSize)
        
        # Refresh and notify settings changed
        internet_set_option(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        internet_set_option(None, INTERNET_OPTION_REFRESH, None, 0)

        logger.info(f"WinINet system proxy configuration: Enable={enable}, Server='{server}', Success={bool(success)}")
        return bool(success)
    except Exception as e:
        logger.error(f"Failed to set system proxy via WinINet API: {e}")
        return False

def restore_proxy_settings():
    """Restores the system proxy settings to the backed-up state before this session."""
    global _has_backup
    if not _has_backup:
        logger.warning("No proxy backup found to restore.")
        return False

    # 1. Restore registry
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE | winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, _backup_enable)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, _backup_server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _backup_override)
    except Exception as e:
        logger.warning(f"Could not restore registry keys: {e}")

    # 2. Restore via WinINet API
    try:
        options = (INTERNET_PER_CONN_OPTION * 3)()
        
        # Flags
        options[0].dwOption = INTERNET_PER_CONN_FLAGS
        # If backup_enable is 1, use proxy flags, otherwise direct flag
        options[0].Value.dwValue = (PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY) if _backup_enable == 1 else PROXY_TYPE_DIRECT
        
        # Store pointers in local variables to prevent garbage collection
        server_ptr = c_wchar_p(_backup_server) if _backup_server else None
        override_ptr = c_wchar_p(_backup_override) if _backup_override else None

        # Server
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER
        options[1].Value.pszValue = server_ptr
        
        # Bypass
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS
        options[2].Value.pszValue = override_ptr

        conn_list = INTERNET_PER_CONN_OPTION_LIST()
        conn_list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST)
        conn_list.pszConnection = None
        conn_list.dwOptionCount = 3
        conn_list.pOptions = options

        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        
        success = internet_set_option(None, INTERNET_OPTION_PER_CONNECTION_OPTION, byref(conn_list), conn_list.dwSize)
        internet_set_option(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        internet_set_option(None, INTERNET_OPTION_REFRESH, None, 0)

        logger.info(f"Original proxy settings restored: Success={bool(success)}")
        return bool(success)
    except Exception as e:
        logger.error(f"Failed to restore system proxy via WinINet API: {e}")
        return False
