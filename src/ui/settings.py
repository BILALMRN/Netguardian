"""
Settings Widget Module for NetGuardian

This module provides the settings widget for the main window.
"""

import os
import logging
import sys
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QGroupBox, QFormLayout, QSpinBox, QComboBox, QMessageBox, QFileDialog
)
from PyQt6.QtGui import QIcon, QPixmap, QFont
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot

from ..utils.db import Database
from ..utils.system import (
    set_autostart, is_autostart_enabled, get_system_info,
    get_network_adapters, restart_network_adapter
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SettingsWidget(QWidget):
    """
    Widget for managing application settings.
    """

    def __init__(self, db: Database):
        """
        Initialize the settings widget.

        Args:
            db: Database instance.
        """
        super().__init__()

        self.db = db

        # Set up the UI
        self._setup_ui()

        # Load initial settings
        self._load_settings()

    def _setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # General settings group
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout(general_group)

        # Start with Windows
        self.autostart_checkbox = QCheckBox("Start with Windows")
        self.autostart_checkbox.toggled.connect(self._on_autostart_toggled)
        general_layout.addRow("", self.autostart_checkbox)

        # Minimize to tray
        self.minimize_to_tray_checkbox = QCheckBox("Minimize to system tray when closed")
        self.minimize_to_tray_checkbox.toggled.connect(self._on_minimize_to_tray_toggled)
        general_layout.addRow("", self.minimize_to_tray_checkbox)

        # Notify for new apps
        self.notify_new_apps_checkbox = QCheckBox("Show notification when new applications are detected")
        self.notify_new_apps_checkbox.toggled.connect(self._on_notify_new_apps_toggled)
        general_layout.addRow("", self.notify_new_apps_checkbox)

        # Update interval
        self.update_interval_spin = QSpinBox()
        self.update_interval_spin.setMinimum(1)
        self.update_interval_spin.setMaximum(60)
        self.update_interval_spin.setSuffix(" seconds")
        self.update_interval_spin.valueChanged.connect(self._on_update_interval_changed)
        general_layout.addRow("Update Interval:", self.update_interval_spin)

        # Add general group to main layout
        main_layout.addWidget(general_group)

        # Network settings group
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout(network_group)

        # Network adapter
        self.adapter_combo = QComboBox()
        self._populate_adapters()
        network_layout.addRow("Network Adapter:", self.adapter_combo)

        # Restart adapter button
        self.restart_adapter_button = QPushButton("Restart Adapter")
        self.restart_adapter_button.clicked.connect(self._on_restart_adapter)
        network_layout.addRow("", self.restart_adapter_button)

        # Add network group to main layout
        main_layout.addWidget(network_group)

        # System information group
        system_group = QGroupBox("System Information")
        system_layout = QFormLayout(system_group)

        # Windows version
        self.windows_version_label = QLabel()
        system_layout.addRow("Windows Version:", self.windows_version_label)

        # Architecture
        self.architecture_label = QLabel()
        system_layout.addRow("Architecture:", self.architecture_label)

        # Computer name
        self.computer_name_label = QLabel()
        system_layout.addRow("Computer Name:", self.computer_name_label)

        # User name
        self.user_name_label = QLabel()
        system_layout.addRow("User Name:", self.user_name_label)

        # Add system group to main layout
        main_layout.addWidget(system_group)

        # Actions group
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_group)

        # Export settings button
        self.export_settings_button = QPushButton("Export Settings")
        self.export_settings_button.clicked.connect(self._on_export_settings)
        actions_layout.addWidget(self.export_settings_button)

        # Import settings button
        self.import_settings_button = QPushButton("Import Settings")
        self.import_settings_button.clicked.connect(self._on_import_settings)
        actions_layout.addWidget(self.import_settings_button)

        # Reset settings button
        self.reset_settings_button = QPushButton("Reset to Default")
        self.reset_settings_button.clicked.connect(self._on_reset_settings)
        actions_layout.addWidget(self.reset_settings_button)

        # Add actions group to main layout
        main_layout.addWidget(actions_group)

        # Add stretch to push everything to the top
        main_layout.addStretch()

        # Load system info
        self._load_system_info()

    def update_data(self, force_update=False):
        """
        Update the settings widget with current data.

        Args:
            force_update: Whether to force an update even if no properties changed.
        """
        # Settings only need to be loaded when the tab is first shown or when forced
        if force_update:
            self._load_settings()

    def _load_settings(self):
        """Load settings from the database."""
        # Autostart
        self.autostart_checkbox.setChecked(is_autostart_enabled("NetGuardian"))

        # Minimize to tray
        minimize_to_tray = self.db.get_setting("minimize_to_tray", True)
        self.minimize_to_tray_checkbox.setChecked(minimize_to_tray)

        # Notify for new apps
        notify_new_apps = self.db.get_setting("notify_new_apps", True)
        self.notify_new_apps_checkbox.setChecked(notify_new_apps)

        # Update interval
        update_interval = self.db.get_setting("update_interval", 1)
        self.update_interval_spin.setValue(update_interval)

        # Network adapter
        adapter = self.db.get_setting("network_adapter", "")
        index = self.adapter_combo.findText(adapter)
        if index >= 0:
            self.adapter_combo.setCurrentIndex(index)

    def _load_system_info(self):
        """Load system information."""
        # Get system info
        info = get_system_info()

        # Set labels
        self.windows_version_label.setText(info.get("windows_version", "Unknown"))
        self.architecture_label.setText(info.get("architecture", "Unknown"))
        self.computer_name_label.setText(info.get("computer_name", "Unknown"))
        self.user_name_label.setText(info.get("user_name", "Unknown"))

    def _populate_adapters(self):
        """Populate the network adapters combo box."""
        # Clear combo box
        self.adapter_combo.clear()

        # Add "All Adapters" option
        self.adapter_combo.addItem("All Adapters")

        # Get network adapters
        adapters = get_network_adapters()

        # Add adapters to combo box
        for adapter in adapters:
            if "name" in adapter:
                self.adapter_combo.addItem(adapter["name"])

    def _on_autostart_toggled(self, checked: bool):
        """
        Handle autostart checkbox toggle.

        Args:
            checked: Whether the checkbox is checked.
        """
        # Get executable path
        executable_path = sys.executable
        if executable_path.endswith("python.exe"):
            # Running from source
            script_path = os.path.abspath(sys.argv[0])
            executable_path = f'"{executable_path}" "{script_path}"'

        # Set autostart
        success = set_autostart("NetGuardian", executable_path, checked)

        if not success:
            QMessageBox.warning(
                self,
                "Error",
                "Failed to set autostart setting."
            )

            # Revert checkbox
            self.autostart_checkbox.setChecked(is_autostart_enabled("NetGuardian"))

    def _on_minimize_to_tray_toggled(self, checked: bool):
        """
        Handle minimize to tray checkbox toggle.

        Args:
            checked: Whether the checkbox is checked.
        """
        self.db.set_setting("minimize_to_tray", checked)

    def _on_notify_new_apps_toggled(self, checked: bool):
        """
        Handle notify for new apps checkbox toggle.

        Args:
            checked: Whether the checkbox is checked.
        """
        self.db.set_setting("notify_new_apps", checked)

    def _on_update_interval_changed(self, value: int):
        """
        Handle update interval change.

        Args:
            value: New update interval value.
        """
        self.db.set_setting("update_interval", value)

    def _on_restart_adapter(self):
        """Handle restart adapter button click."""
        # Get selected adapter
        adapter = self.adapter_combo.currentText()

        if adapter == "All Adapters":
            QMessageBox.warning(
                self,
                "Error",
                "Please select a specific network adapter to restart."
            )
            return

        # Confirm restart
        result = QMessageBox.question(
            self,
            "Confirm Restart",
            f"Are you sure you want to restart the network adapter '{adapter}'?\n"
            "This will temporarily disconnect your network connection.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        # Restart adapter
        success = restart_network_adapter(adapter)

        if success:
            QMessageBox.information(
                self,
                "Success",
                f"Network adapter '{adapter}' has been restarted."
            )
        else:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to restart network adapter '{adapter}'.\n"
                "Administrator privileges may be required."
            )

    def _on_export_settings(self):
        """Handle export settings button click."""
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Settings",
            "",
            "JSON Files (*.json)"
        )

        if not file_path:
            return

        # Add .json extension if not present
        if not file_path.lower().endswith(".json"):
            file_path += ".json"

        # Get all settings
        settings = self.db.get_all_settings()

        # Export settings
        try:
            import json
            with open(file_path, "w") as f:
                json.dump(settings, f, indent=4)

            QMessageBox.information(
                self,
                "Success",
                f"Settings have been exported to '{file_path}'."
            )
        except Exception as e:
            logger.error(f"Error exporting settings: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to export settings: {str(e)}"
            )

    def _on_import_settings(self):
        """Handle import settings button click."""
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Settings",
            "",
            "JSON Files (*.json)"
        )

        if not file_path:
            return

        # Import settings
        try:
            import json
            with open(file_path, "r") as f:
                settings = json.load(f)

            # Validate settings
            if not isinstance(settings, dict):
                raise ValueError("Invalid settings file format")

            # Apply settings
            for key, value in settings.items():
                self.db.set_setting(key, value)

            QMessageBox.information(
                self,
                "Success",
                f"Settings have been imported from '{file_path}'."
            )

            # Reload settings
            self._load_settings()
        except Exception as e:
            logger.error(f"Error importing settings: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to import settings: {str(e)}"
            )

    def _on_reset_settings(self):
        """Handle reset settings button click."""
        # Confirm reset
        result = QMessageBox.question(
            self,
            "Confirm Reset",
            "Are you sure you want to reset all settings to default?\n"
            "This will not affect firewall rules or application list.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        # Default settings
        default_settings = {
            "minimize_to_tray": True,
            "notify_new_apps": True,
            "update_interval": 1
        }

        # Apply default settings
        for key, value in default_settings.items():
            self.db.set_setting(key, value)

        QMessageBox.information(
            self,
            "Success",
            "Settings have been reset to default."
        )

        # Reload settings
        self._load_settings()
