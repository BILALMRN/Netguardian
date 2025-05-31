"""
Application Detector Module for NetGuardian

This module provides functionality for detecting installed applications
and monitoring for new applications.
"""

import os
import psutil
import logging
import threading
import time
import winreg
import random
from typing import List, Dict, Optional, Set, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AppInfo:
    """
    Represents information about an application.
    """

    def __init__(self,
                path: str,
                name: Optional[str] = None,
                description: Optional[str] = None,
                publisher: Optional[str] = None,
                icon_path: Optional[str] = None):
        """
        Initialize application information.

        Args:
            path: Path to the application executable.
            name: Name of the application.
            description: Description of the application.
            publisher: Publisher of the application.
            icon_path: Path to the application icon.
        """
        self.path = path
        self.name = name or os.path.basename(path)
        self.description = description
        self.publisher = publisher
        self.icon_path = icon_path

    def to_dict(self) -> Dict:
        """
        Convert the application info to a dictionary.

        Returns:
            Dictionary representation of the application info.
        """
        return {
            "path": self.path,
            "name": self.name,
            "description": self.description,
            "publisher": self.publisher,
            "icon_path": self.icon_path
        }


class AppDetector:
    """
    Detects installed applications and monitors for new applications.
    """

    def __init__(self, scan_interval: float = 600.0):
        """
        Initialize the application detector.

        Args:
            scan_interval: Interval in seconds between scans for new applications.
        """
        self.scan_interval = scan_interval
        self.apps = {}  # key: path, value: AppInfo
        self.running = False
        self.scan_thread = None
        self._lock = threading.Lock()
        self._new_app_callbacks = []
        self._initial_scan_complete = False

    def start(self) -> None:
        """Start monitoring for applications."""
        if self.running:
            return

        self.running = True
        self.scan_thread = threading.Thread(target=self._scan_loop)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        logger.info("Application monitoring started")

    def stop(self) -> None:
        """Stop monitoring for applications."""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=2.0)
            self.scan_thread = None
        logger.info("Application monitoring stopped")

    def register_new_app_callback(self, callback) -> None:
        """
        Register a callback for new application detection.

        Args:
            callback: Function to call when a new application is detected.
                     The function should accept an AppInfo object as its argument.
        """
        self._new_app_callbacks.append(callback)

    def _scan_loop(self) -> None:
        """Main scanning loop."""
        # Initial scan - only scan processes for faster startup
        logger.info("Starting initial process scan")
        self._scan_processes()
        self._initial_scan_complete = True

        # Schedule the registry scan after a longer delay (10 seconds)
        logger.info("Scheduling registry scan in 10 seconds")
        time.sleep(10.0)

        # Perform registry scan
        if self.running:
            logger.info("Starting registry scan")
            self._scan_registry()

        # Schedule directory scan after another delay (30 seconds)
        logger.info("Scheduling directory scan in 30 seconds")
        time.sleep(30.0)

        # Main monitoring loop - only scan processes regularly
        while self.running:
            try:
                # Only scan processes during regular operation
                self._scan_processes()

                # Occasionally scan registry (once per hour)
                if random.random() < 0.01:  # ~1% chance each cycle = ~once per hour
                    logger.info("Performing periodic registry scan")
                    self._scan_registry()

                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Error in application scanning: {e}")
                time.sleep(10.0)  # Sleep a bit to avoid tight loop on error

    def _scan_for_apps_full(self) -> None:
        """Perform a full scan for installed applications."""
        # This method is no longer used - we've split the scans
        pass

    def _scan_processes(self) -> None:
        """Scan running processes for applications."""
        new_apps = []

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe'] and proc.info['exe'].lower().endswith('.exe'):
                    path = proc.info['exe']

                    with self._lock:
                        if path not in self.apps:
                            # New application found
                            app_info = AppInfo(
                                path=path,
                                name=proc.info['name']
                            )
                            self.apps[path] = app_info
                            new_apps.append(app_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Notify about new applications
        for app in new_apps:
            for callback in self._new_app_callbacks:
                try:
                    callback(app)
                except Exception as e:
                    logger.error(f"Error in new app callback: {e}")

    def _scan_registry(self) -> None:
        """Scan Windows registry for installed applications."""
        new_apps = []

        try:
            # Scan 64-bit applications
            self._scan_registry_key(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                new_apps
            )

            # Scan 32-bit applications on 64-bit Windows
            self._scan_registry_key(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                new_apps
            )

            # Scan user-specific applications
            self._scan_registry_key(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                new_apps
            )
        except Exception as e:
            logger.error(f"Error scanning registry: {e}")

        # Notify about new applications
        for app in new_apps:
            for callback in self._new_app_callbacks:
                try:
                    callback(app)
                except Exception as e:
                    logger.error(f"Error in new app callback: {e}")

    def _scan_registry_key(self, hkey, key_path, new_apps) -> None:
        """
        Scan a registry key for installed applications.

        Args:
            hkey: Registry hive.
            key_path: Path to the registry key.
            new_apps: List to append new applications to.
        """
        try:
            key = winreg.OpenKey(hkey, key_path)

            # Limit the number of registry entries to scan for better performance
            max_entries = 100
            num_entries = min(winreg.QueryInfoKey(key)[0], max_entries)

            for i in range(num_entries):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)

                    try:
                        # Get only the essential values
                        path = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]

                        # Publisher is optional
                        try:
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except (FileNotFoundError, OSError):
                            publisher = "Unknown"
                    except (FileNotFoundError, OSError):
                        continue

                    if path and display_name:
                        # Look for main executable instead of scanning all files
                        # First check for common executable patterns
                        potential_exes = [
                            os.path.join(path, display_name + ".exe"),
                            os.path.join(path, "bin", display_name + ".exe"),
                            os.path.join(path, "program", display_name + ".exe")
                        ]

                        found_exe = False
                        for exe_path in potential_exes:
                            if os.path.isfile(exe_path):
                                with self._lock:
                                    if exe_path not in self.apps:
                                        # New application found
                                        app_info = AppInfo(
                                            path=exe_path,
                                            name=display_name,
                                            publisher=publisher
                                        )
                                        self.apps[exe_path] = app_info
                                        new_apps.append(app_info)
                                found_exe = True
                                break

                        # If no exe found with common patterns, look in the root directory only
                        if not found_exe:
                            try:
                                for item in os.listdir(path):
                                    if item.lower().endswith('.exe'):
                                        exe_path = os.path.join(path, item)

                                        with self._lock:
                                            if exe_path not in self.apps:
                                                # New application found
                                                app_info = AppInfo(
                                                    path=exe_path,
                                                    name=display_name,
                                                    publisher=publisher
                                                )
                                                self.apps[exe_path] = app_info
                                                new_apps.append(app_info)
                                        break  # Only add the first exe found
                            except (PermissionError, FileNotFoundError):
                                pass

                    winreg.CloseKey(subkey)
                except (FileNotFoundError, OSError):
                    continue

            winreg.CloseKey(key)
        except (FileNotFoundError, OSError) as e:
            logger.error(f"Error opening registry key {key_path}: {e}")

    def _scan_program_dirs(self) -> None:
        """Scan common program directories for applications."""
        new_apps = []

        # Focus on the most important program directories for better performance
        program_dirs = [
            os.path.join(os.environ["ProgramFiles"], "Microsoft"),
            os.path.join(os.environ["ProgramFiles"], "Google"),
            os.path.join(os.environ["ProgramFiles"], "Mozilla Firefox"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Microsoft"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Google"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Mozilla Firefox"),
            os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs")
        ]

        # Limit the number of directories to scan
        max_dirs = 20
        dir_count = 0

        for program_dir in program_dirs:
            if os.path.exists(program_dir) and dir_count < max_dirs:
                self._scan_dir_for_exes(program_dir, new_apps, max_depth=2)
                dir_count += 1

        # Notify about new applications in batches
        if new_apps:
            for callback in self._new_app_callbacks:
                try:
                    # Process apps in batches to avoid UI freezing
                    batch_size = 5
                    for i in range(0, len(new_apps), batch_size):
                        batch = new_apps[i:i+batch_size]
                        for app in batch:
                            callback(app)
                except Exception as e:
                    logger.error(f"Error in new app callback: {e}")

    def _scan_dir_for_exes(self, directory, new_apps, max_depth=2, current_depth=0) -> None:
        """
        Recursively scan a directory for executable files.

        Args:
            directory: Directory to scan.
            new_apps: List to append new applications to.
            max_depth: Maximum recursion depth.
            current_depth: Current recursion depth.
        """
        if current_depth > max_depth:
            return

        try:
            # Limit the number of files to check per directory
            max_files = 50
            file_count = 0

            items = os.listdir(directory)

            # First check for exe files
            for item in items:
                if file_count >= max_files:
                    break

                path = os.path.join(directory, item)

                if os.path.isfile(path) and path.lower().endswith('.exe'):
                    file_count += 1
                    with self._lock:
                        if path not in self.apps:
                            # New application found
                            app_info = AppInfo(
                                path=path,
                                name=os.path.splitext(item)[0]
                            )
                            self.apps[path] = app_info
                            new_apps.append(app_info)

            # Then check subdirectories if we haven't reached the limit
            if current_depth < max_depth:
                for item in items:
                    path = os.path.join(directory, item)
                    if os.path.isdir(path):
                        self._scan_dir_for_exes(path, new_apps, max_depth, current_depth + 1)

        except (PermissionError, FileNotFoundError) as e:
            logger.debug(f"Error scanning directory {directory}: {e}")

    def get_all_apps(self) -> List[Dict]:
        """
        Get all detected applications.

        Returns:
            List of application dictionaries.
        """
        with self._lock:
            return [app.to_dict() for app in self.apps.values()]

    def get_app_info(self, path: str) -> Optional[Dict]:
        """
        Get information about a specific application.

        Args:
            path: Path to the application executable.

        Returns:
            Application info dictionary or None if not found.
        """
        with self._lock:
            app = self.apps.get(path)
            return app.to_dict() if app else None
