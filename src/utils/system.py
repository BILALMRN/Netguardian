"""
System Utility Module for NetGuardian

This module provides system-level utility functions.
"""

import os
import sys
import ctypes
import logging
import subprocess
import winreg
from typing import Optional, List, Dict, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def is_admin() -> bool:
    """
    Check if the application is running with administrator privileges.
    
    Returns:
        True if running as administrator, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False

def run_as_admin(executable_path: str, args: Optional[List[str]] = None) -> None:
    """
    Run the application as administrator.
    
    Args:
        executable_path: Path to the executable.
        args: Optional list of command-line arguments.
    """
    if args is None:
        args = []
    
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable_path, " ".join(args), None, 1
        )
    except Exception as e:
        logger.error(f"Error running as admin: {e}")
        raise

def get_app_data_dir(app_name: str) -> str:
    """
    Get the application data directory.
    
    Args:
        app_name: Name of the application.
        
    Returns:
        Path to the application data directory.
    """
    app_data = os.environ.get('APPDATA')
    if not app_data:
        app_data = os.path.expanduser('~')
    
    app_dir = os.path.join(app_data, app_name)
    os.makedirs(app_dir, exist_ok=True)
    
    return app_dir

def set_autostart(app_name: str, executable_path: str, enabled: bool = True) -> bool:
    """
    Set the application to start automatically with Windows.
    
    Args:
        app_name: Name of the application.
        executable_path: Path to the executable.
        enabled: Whether to enable or disable autostart.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        if enabled:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, executable_path)
        else:
            try:
                winreg.DeleteValue(key, app_name)
            except FileNotFoundError:
                pass  # Key doesn't exist, which is fine
        
        winreg.CloseKey(key)
        return True
    
    except Exception as e:
        logger.error(f"Error setting autostart: {e}")
        return False

def is_autostart_enabled(app_name: str) -> bool:
    """
    Check if autostart is enabled for the application.
    
    Args:
        app_name: Name of the application.
        
    Returns:
        True if autostart is enabled, False otherwise.
    """
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        )
        
        try:
            winreg.QueryValueEx(key, app_name)
            enabled = True
        except FileNotFoundError:
            enabled = False
        
        winreg.CloseKey(key)
        return enabled
    
    except Exception as e:
        logger.error(f"Error checking autostart: {e}")
        return False

def create_shortcut(target_path: str, shortcut_path: str, 
                   description: Optional[str] = None, 
                   icon_path: Optional[str] = None) -> bool:
    """
    Create a Windows shortcut.
    
    Args:
        target_path: Path to the target executable.
        shortcut_path: Path where the shortcut will be created.
        description: Optional description for the shortcut.
        icon_path: Optional path to the icon file.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        import pythoncom
        from win32com.client import Dispatch
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target_path
        
        if description:
            shortcut.Description = description
        
        if icon_path:
            shortcut.IconLocation = icon_path
        
        shortcut.save()
        return True
    
    except Exception as e:
        logger.error(f"Error creating shortcut: {e}")
        return False

def get_system_info() -> Dict[str, str]:
    """
    Get system information.
    
    Returns:
        Dictionary with system information.
    """
    info = {}
    
    try:
        # Windows version
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        info['windows_version'] = winreg.QueryValueEx(key, "ProductName")[0]
        info['build_number'] = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
        winreg.CloseKey(key)
        
        # System architecture
        if 'PROCESSOR_ARCHITECTURE' in os.environ:
            info['architecture'] = os.environ['PROCESSOR_ARCHITECTURE']
        
        # Python version
        info['python_version'] = sys.version
        
        # Computer name
        info['computer_name'] = os.environ.get('COMPUTERNAME', 'Unknown')
        
        # User name
        info['user_name'] = os.environ.get('USERNAME', 'Unknown')
    
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
    
    return info

def get_network_adapters() -> List[Dict[str, str]]:
    """
    Get information about network adapters.
    
    Returns:
        List of dictionaries with network adapter information.
    """
    adapters = []
    
    try:
        # Use ipconfig to get adapter information
        result = subprocess.run(
            ["ipconfig", "/all"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        lines = result.stdout.splitlines()
        current_adapter = None
        
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            
            # New adapter section
            if not line.startswith(" ") and "adapter" in line.lower():
                if current_adapter:
                    adapters.append(current_adapter)
                
                adapter_name = line.split(":", 1)[0].strip()
                current_adapter = {"name": adapter_name}
            
            # Adapter property
            elif current_adapter and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                
                if value:
                    current_adapter[key] = value
        
        # Add the last adapter
        if current_adapter:
            adapters.append(current_adapter)
    
    except Exception as e:
        logger.error(f"Error getting network adapters: {e}")
    
    return adapters

def restart_network_adapter(adapter_name: str) -> bool:
    """
    Restart a network adapter.
    
    Args:
        adapter_name: Name of the network adapter.
        
    Returns:
        True if successful, False otherwise.
    """
    if not is_admin():
        logger.error("Administrator privileges required to restart network adapter")
        return False
    
    try:
        # Disable the adapter
        subprocess.run(
            ["netsh", "interface", "set", "interface", adapter_name, "admin=disable"],
            check=True
        )
        
        # Wait a moment
        import time
        time.sleep(2)
        
        # Enable the adapter
        subprocess.run(
            ["netsh", "interface", "set", "interface", adapter_name, "admin=enable"],
            check=True
        )
        
        return True
    
    except Exception as e:
        logger.error(f"Error restarting network adapter: {e}")
        return False
