"""
Application List Widget Module for NetGuardian

This module provides the application list widget for the main window.
"""

import os
import logging
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QMenu,
    QAbstractItemView, QMessageBox, QFileDialog, QComboBox, QApplication
)
from PyQt6.QtGui import QIcon, QPixmap, QAction, QFont, QColor, QImage
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot, QTimer

from ..firewall.manager import FirewallManager
from ..monitoring.connections import ConnectionMonitor
from ..utils.db import Database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AppListWidget(QWidget):
    """
    Widget for displaying and managing the list of applications.
    """

    def __init__(self, firewall_manager: FirewallManager, db: Database,
                connection_monitor: ConnectionMonitor):
        """
        Initialize the application list widget.

        Args:
            firewall_manager: Firewall manager instance.
            db: Database instance.
            connection_monitor: Connection monitor instance.
        """
        super().__init__()

        self.firewall_manager = firewall_manager
        self.db = db
        self.connection_monitor = connection_monitor

        # Set up the UI
        self._setup_ui()

        # Flag to prevent multiple updates
        self._is_updating = False

        # Load initial data - but only once
        QTimer.singleShot(500, lambda: self._load_data_once())

    def _setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create search and filter bar
        filter_layout = QHBoxLayout()

        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search applications...")
        self.search_input.textChanged.connect(self._filter_apps)
        filter_layout.addWidget(self.search_input)

        # Filter dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Applications", "all")
        self.filter_combo.addItem("Blocked Applications", "blocked")
        self.filter_combo.addItem("Allowed Applications", "allowed")
        self.filter_combo.addItem("Active Applications", "active")
        self.filter_combo.currentIndexChanged.connect(self._filter_apps)
        filter_layout.addWidget(self.filter_combo)

        # Add application button
        self.add_app_button = QPushButton("Add Application")
        self.add_app_button.clicked.connect(self._add_application)
        filter_layout.addWidget(self.add_app_button)

        # Add filter layout to main layout
        main_layout.addLayout(filter_layout)

        # Create table widget
        self.app_table = QTableWidget()
        self.app_table.setColumnCount(4)
        self.app_table.setHorizontalHeaderLabels(["Name", "Path", "Status", "Actions"])
        self.app_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.app_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.app_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.app_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.app_table.verticalHeader().setVisible(False)
        self.app_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.app_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.app_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.app_table.customContextMenuRequested.connect(self._show_context_menu)

        # Add table to main layout
        main_layout.addWidget(self.app_table)

        # Create status bar
        status_layout = QHBoxLayout()

        self.status_label = QLabel("0 applications")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        # Batch actions
        self.batch_block_button = QPushButton("Block Selected")
        self.batch_block_button.clicked.connect(self._batch_block)
        status_layout.addWidget(self.batch_block_button)

        self.batch_allow_button = QPushButton("Allow Selected")
        self.batch_allow_button.clicked.connect(self._batch_allow)
        status_layout.addWidget(self.batch_allow_button)

        # Add status layout to main layout
        main_layout.addLayout(status_layout)

    def _load_data_once(self):
        """Load the app list data exactly once."""
        if not self._is_updating:
            self._is_updating = True
            logger.info("Loading app list data (one-time load)")
            # Apply current filter - this will get apps from database
            self._filter_apps()
            self._is_updating = False

    def update_data(self, force_update=False):
        """
        Update the application list with current data.

        Args:
            force_update: Whether to force an update even if no properties changed.
        """
        # Only update when explicitly forced and not already updating
        if force_update and not self._is_updating:
            self._is_updating = True
            logger.info("Forced update of app list data")
            # Apply current filter - this will get apps from database
            self._filter_apps()
            self._is_updating = False

    def _filter_apps(self):
        """Filter the application list based on search and filter criteria."""
        try:
            # Get all apps from database with cache
            apps = self.db.get_all_apps(use_cache=True)

            # Get search text
            search_text = self.search_input.text().lower()

            # Get filter type
            filter_type = self.filter_combo.currentData()

            # Filter apps
            filtered_apps = []

            # Group apps by folder path
            folder_groups = {}

            for app in apps:
                # Apply search filter
                if search_text and search_text not in app["name"].lower() and search_text not in app["path"].lower():
                    continue

                # Apply type filter
                if filter_type == "blocked" and not app["is_blocked"]:
                    continue
                elif filter_type == "allowed" and app["is_blocked"]:
                    continue
                elif filter_type == "active":
                    # Check if app has active connections - this can be slow
                    try:
                        connections = self.connection_monitor.get_app_connections(app["path"])
                        if not connections:
                            continue
                    except Exception:
                        continue

                # Get folder path
                folder_path = os.path.dirname(app["path"])

                # Add to folder group
                if folder_path not in folder_groups:
                    folder_groups[folder_path] = []
                folder_groups[folder_path].append(app)

            # For each folder, add the first app and set a special flag
            for folder_path, group_apps in folder_groups.items():
                # Sort apps by name
                group_apps.sort(key=lambda a: a["name"])

                # Add first app with folder info
                if len(group_apps) > 1:
                    first_app = group_apps[0].copy()
                    first_app["is_folder"] = True
                    first_app["folder_path"] = folder_path
                    first_app["app_count"] = len(group_apps)
                    first_app["folder_apps"] = group_apps
                    filtered_apps.append(first_app)
                else:
                    # Just add the single app
                    filtered_apps.append(group_apps[0])

            # Update table directly
            self._update_table(filtered_apps)

            # Update status
            self.status_label.setText(f"{len(filtered_apps)} applications")
        except Exception as e:
            logger.error(f"Error filtering apps: {e}")

    def _update_table(self, apps: List[Dict[str, Any]]):
        """
        Update the table with the given applications.

        Args:
            apps: List of application dictionaries.
        """
        try:
            # Temporarily disable sorting to improve performance
            self.app_table.setSortingEnabled(False)

            # Disable UI updates during table population
            self.app_table.setUpdatesEnabled(False)

            # Remember the current selection
            selected_paths = []
            for index in self.app_table.selectionModel().selectedRows():
                row = index.row()
                if row < self.app_table.rowCount():
                    path_item = self.app_table.item(row, 1)
                    if path_item:
                        selected_paths.append(path_item.text())

            # Clear table
            self.app_table.setRowCount(0)

            # Add apps to table in batches for better performance
            batch_size = 10
            for batch_start in range(0, len(apps), batch_size):
                batch_end = min(batch_start + batch_size, len(apps))
                batch = apps[batch_start:batch_end]

                for app in batch:
                    row = self.app_table.rowCount()
                    self.app_table.insertRow(row)

                    # Check if this is a folder entry
                    if app.get("is_folder", False):
                        # This is a folder entry - show folder name with app count
                        folder_name = os.path.basename(app["folder_path"])
                        if not folder_name:
                            folder_name = app["folder_path"]  # Use full path if basename is empty

                        name_item = QTableWidgetItem(f"{folder_name} ({app['app_count']} apps)")

                        # Use folder icon
                        from PyQt6.QtWidgets import QFileIconProvider
                        from PyQt6.QtCore import QFileInfo

                        icon_provider = QFileIconProvider()
                        folder_icon = icon_provider.icon(QFileIconProvider.IconType.Folder)
                        name_item.setIcon(folder_icon)

                        # Set font to bold
                        font = name_item.font()
                        font.setBold(True)
                        name_item.setFont(font)

                        # Store folder info in item data
                        name_item.setData(Qt.ItemDataRole.UserRole, app)
                    else:
                        # Regular app entry
                        name_item = QTableWidgetItem(app["name"])

                        # Try to get app icon using a simpler method
                        try:
                            if os.path.exists(app["path"]):
                                # Use QFileIconProvider to get the icon
                                from PyQt6.QtWidgets import QFileIconProvider
                                from PyQt6.QtCore import QFileInfo

                                icon_provider = QFileIconProvider()
                                file_info = QFileInfo(app["path"])
                                icon = icon_provider.icon(file_info)

                                if not icon.isNull():
                                    name_item.setIcon(icon)
                        except Exception as e:
                            # If we can't get the icon, just use a default one
                            logger.debug(f"Failed to get icon for {app['path']}: {e}")

                    self.app_table.setItem(row, 0, name_item)

                    # Path
                    path_item = QTableWidgetItem(app["path"])
                    self.app_table.setItem(row, 1, path_item)

                    # Status
                    status_item = QTableWidgetItem()
                    status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    if app["is_blocked"]:
                        status_item.setText("Blocked")
                        status_item.setForeground(QColor(255, 0, 0))  # Red
                    else:
                        status_item.setText("Allowed")
                        status_item.setForeground(QColor(0, 128, 0))  # Green
                    self.app_table.setItem(row, 2, status_item)

                    # Actions
                    actions_widget = QWidget()
                    actions_layout = QHBoxLayout(actions_widget)
                    actions_layout.setContentsMargins(4, 4, 4, 4)

                    # Toggle button
                    toggle_button = QPushButton()
                    if app["is_blocked"]:
                        toggle_button.setText("Allow")
                        toggle_button.setStyleSheet("background-color: #4CAF50; color: white;")
                    else:
                        toggle_button.setText("Block")
                        toggle_button.setStyleSheet("background-color: #F44336; color: white;")

                    # Use a lambda with default argument to capture the current app
                    toggle_button.clicked.connect(lambda checked, a=app: self._toggle_app_status(a))

                    actions_layout.addWidget(toggle_button)

                    # Details button
                    details_button = QPushButton("Details")
                    details_button.clicked.connect(lambda checked, a=app: self._show_app_details(a))
                    actions_layout.addWidget(details_button)

                    self.app_table.setCellWidget(row, 3, actions_widget)

                # Process events to keep UI responsive
                QApplication.processEvents()

            # No need to update traffic information anymore

            # Restore selection
            if selected_paths:
                for row in range(self.app_table.rowCount()):
                    path_item = self.app_table.item(row, 1)
                    if path_item and path_item.text() in selected_paths:
                        self.app_table.selectRow(row)

            # Re-enable sorting and updates
            self.app_table.setSortingEnabled(True)
            self.app_table.setUpdatesEnabled(True)

        except Exception as e:
            logger.error(f"Error updating table: {e}")

    def _update_traffic_info(self, apps: List[Dict[str, Any]]):
        """Update traffic information for apps in the table."""
        try:
            # Find apps in the table
            for row in range(self.app_table.rowCount()):
                path_item = self.app_table.item(row, 1)
                if not path_item:
                    continue

                path = path_item.text()

                # Find the app in our list
                app = next((a for a in apps if a["path"] == path), None)
                if not app:
                    continue

                # Get traffic info
                try:
                    traffic = self.connection_monitor.get_app_traffic(path)
                    traffic_text = f"↑ {self._format_bytes(traffic['send_rate'])}/s | ↓ {self._format_bytes(traffic['recv_rate'])}/s"

                    # Update the traffic item
                    traffic_item = self.app_table.item(row, 3)
                    if traffic_item:
                        traffic_item.setText(traffic_text)
                except Exception:
                    # If we can't get traffic info, just show "No traffic"
                    traffic_item = self.app_table.item(row, 3)
                    if traffic_item:
                        traffic_item.setText("No traffic")

                # Process events occasionally to keep UI responsive
                if row % 10 == 0:
                    QApplication.processEvents()

        except Exception as e:
            logger.error(f"Error updating traffic info: {e}")

    def _format_bytes(self, bytes_value: float) -> str:
        """
        Format bytes value to human-readable string.

        Args:
            bytes_value: Value in bytes.

        Returns:
            Formatted string.
        """
        if bytes_value < 1024:
            return f"{bytes_value:.0f} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.1f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.1f} GB"

    def _toggle_app_status(self, app: Dict[str, Any]):
        """
        Toggle an application's blocked status.

        Args:
            app: Application dictionary.
        """
        # Check if this is a folder entry
        if app.get("is_folder", False):
            # Ask user if they want to toggle all apps in the folder
            folder_apps = app.get("folder_apps", [])
            folder_path = app.get("folder_path", "")

            # Determine the action based on the first app's status
            is_blocked = folder_apps[0].get("is_blocked", False)
            action = "allow" if is_blocked else "block"

            result = QMessageBox.question(
                self,
                f"{action.capitalize()} All Apps",
                f"Do you want to {action} all {len(folder_apps)} applications in this folder?\n\n"
                f"Folder: {folder_path}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if result != QMessageBox.StandardButton.Yes:
                return

            # Check for admin privileges
            if not self.firewall_manager.has_admin:
                QMessageBox.warning(
                    self,
                    "Administrator Privileges Required",
                    f"NetGuardian requires administrator privileges to modify firewall rules.\n"
                    "Please restart the application as administrator."
                )
                return

            # Toggle all apps in the folder
            success_count = 0
            for folder_app in folder_apps:
                if is_blocked:
                    # Allow the app
                    success = self.firewall_manager.allow_app(folder_app["path"])
                    if success:
                        self.db.set_app_blocked(folder_app["path"], False)
                        success_count += 1
                else:
                    # Block the app
                    success = self.firewall_manager.block_app(folder_app["path"])
                    if success:
                        self.db.set_app_blocked(folder_app["path"], True)
                        success_count += 1

            # Show result
            QMessageBox.information(
                self,
                "Operation Complete",
                f"Successfully {action}ed {success_count} of {len(folder_apps)} applications."
            )

            # Update the UI
            self.update_data(force_update=True)
            return

        # Regular app toggle
        path = app["path"]
        is_blocked = app["is_blocked"]

        if is_blocked:
            # Allow the app
            success = self.firewall_manager.allow_app(path)
            if success:
                self.db.set_app_blocked(path, False)
                logger.info(f"Allowed application: {path}")
            else:
                if not self.firewall_manager.has_admin:
                    QMessageBox.warning(
                        self,
                        "Administrator Privileges Required",
                        f"Failed to allow application: {app['name']}\n\n"
                        "NetGuardian requires administrator privileges to modify firewall rules.\n"
                        "Please restart the application as administrator."
                    )
                else:
                    QMessageBox.warning(
                        self,
                        "Error",
                        f"Failed to allow application: {app['name']}"
                    )
        else:
            # Block the app
            success = self.firewall_manager.block_app(path)
            if success:
                self.db.set_app_blocked(path, True)
                logger.info(f"Blocked application: {path}")
            else:
                if not self.firewall_manager.has_admin:
                    QMessageBox.warning(
                        self,
                        "Administrator Privileges Required",
                        f"Failed to block application: {app['name']}\n\n"
                        "NetGuardian requires administrator privileges to modify firewall rules.\n"
                        "Please restart the application as administrator."
                    )
                else:
                    QMessageBox.warning(
                        self,
                        "Error",
                        f"Failed to block application: {app['name']}"
                    )

        # Update the UI with force_update=True since properties changed
        self.update_data(force_update=True)

    def _show_app_details(self, app: Dict[str, Any]):
        """
        Show application details.

        Args:
            app: Application dictionary.
        """
        # Check if this is a folder entry
        if app.get("is_folder", False):
            # Show folder details
            folder_apps = app.get("folder_apps", [])
            folder_path = app.get("folder_path", "")

            # Create a list of apps in the folder
            apps_text = ""
            for folder_app in folder_apps:
                status = "Blocked" if folder_app.get("is_blocked", False) else "Allowed"
                apps_text += f"• {folder_app['name']} ({status})\n"

            # Show folder details dialog
            QMessageBox.information(
                self,
                f"Folder Details: {os.path.basename(folder_path)}",
                f"Folder Path: {folder_path}\n"
                f"Number of Applications: {len(folder_apps)}\n\n"
                f"Applications in this folder:\n{apps_text}"
            )
            return

        # Regular app details
        # Get connections for the app
        connections = self.connection_monitor.get_app_connections(app["path"])

        # Get daily traffic statistics
        daily_traffic = self.connection_monitor.get_app_daily_traffic(app["path"])
        daily_sent = self._format_bytes(daily_traffic["daily_bytes_sent"])
        daily_recv = self._format_bytes(daily_traffic["daily_bytes_recv"])

        # Format connections
        connections_text = ""
        for conn in connections:
            connections_text += f"Local: {conn['local_addr']} | Remote: {conn['remote_addr']} | {conn['type']} | {conn['status']}\n"

        if not connections_text:
            connections_text = "No active connections"

        # Show details dialog
        QMessageBox.information(
            self,
            f"Details: {app['name']}",
            f"Path: {app['path']}\n"
            f"Publisher: {app.get('publisher', 'Unknown')}\n"
            f"Status: {'Blocked' if app['is_blocked'] else 'Allowed'}\n\n"
            f"Daily Traffic (since 00:00):\n"
            f"↑ Uploaded: {daily_sent}\n"
            f"↓ Downloaded: {daily_recv}\n\n"
            f"Active Connections:\n{connections_text}"
        )

    def _show_context_menu(self, position):
        """
        Show context menu for the application table.

        Args:
            position: Position where the menu should be shown.
        """
        # Get selected rows
        selected_rows = self.app_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        # Create menu
        menu = QMenu()

        # Add actions
        allow_action = QAction("Allow", self)
        allow_action.triggered.connect(self._batch_allow)
        menu.addAction(allow_action)

        block_action = QAction("Block", self)
        block_action.triggered.connect(self._batch_block)
        menu.addAction(block_action)

        menu.addSeparator()

        remove_action = QAction("Remove", self)
        remove_action.triggered.connect(self._remove_selected)
        menu.addAction(remove_action)

        # Show menu
        menu.exec(self.app_table.mapToGlobal(position))

    def _batch_allow(self):
        """Allow all selected applications."""
        # Get selected rows
        selected_rows = self.app_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        # Check for admin privileges first
        if not self.firewall_manager.has_admin:
            QMessageBox.warning(
                self,
                "Administrator Privileges Required",
                "NetGuardian requires administrator privileges to modify firewall rules.\n"
                "Please restart the application as administrator."
            )
            return

        # Allow each selected app
        for index in selected_rows:
            row = index.row()
            path = self.app_table.item(row, 1).text()

            # Allow the app
            success = self.firewall_manager.allow_app(path)
            if success:
                self.db.set_app_blocked(path, False)
                logger.info(f"Allowed application: {path}")

        # Update the UI with force_update=True since properties changed
        self.update_data(force_update=True)

    def _batch_block(self):
        """Block all selected applications."""
        # Get selected rows
        selected_rows = self.app_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        # Check for admin privileges first
        if not self.firewall_manager.has_admin:
            QMessageBox.warning(
                self,
                "Administrator Privileges Required",
                "NetGuardian requires administrator privileges to modify firewall rules.\n"
                "Please restart the application as administrator."
            )
            return

        # Block each selected app
        for index in selected_rows:
            row = index.row()
            path = self.app_table.item(row, 1).text()

            # Block the app
            success = self.firewall_manager.block_app(path)
            if success:
                self.db.set_app_blocked(path, True)
                logger.info(f"Blocked application: {path}")

        # Update the UI with force_update=True since properties changed
        self.update_data(force_update=True)

    def _remove_selected(self):
        """Remove selected applications from the list."""
        # Get selected rows
        selected_rows = self.app_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        # Confirm removal
        result = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove {len(selected_rows)} application(s) from the list?\n"
            "This will also remove any firewall rules for these applications.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        # Check for admin privileges if we need to remove firewall rules
        admin_warning_shown = False
        if not self.firewall_manager.has_admin:
            QMessageBox.warning(
                self,
                "Administrator Privileges Required",
                "NetGuardian requires administrator privileges to remove firewall rules.\n"
                "The applications will be removed from the list, but firewall rules may remain.\n"
                "Please restart the application as administrator to fully remove rules."
            )
            admin_warning_shown = True

        # Remove each selected app
        for index in selected_rows:
            row = index.row()
            path = self.app_table.item(row, 1).text()

            # Remove firewall rules if we have admin privileges
            if self.firewall_manager.has_admin:
                self.firewall_manager.remove_app_rules(path)

            # Remove from database
            self.db.delete_app(path)

            logger.info(f"Removed application: {path}")

        # Update the UI with force_update=True since properties changed
        self.update_data(force_update=True)

    def _add_application(self):
        """Add a new application to the list."""
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Application",
            "",
            "Executable Files (*.exe)"
        )

        if not file_path:
            return

        # Check if app already exists
        app = self.db.get_app(file_path)
        if app:
            QMessageBox.information(
                self,
                "Application Already Exists",
                f"The application '{os.path.basename(file_path)}' is already in the list."
            )
            return

        # Add app to database
        self.db.save_app(
            path=file_path,
            name=os.path.basename(file_path),
            is_blocked=False  # Default to allowed
        )

        # Update the UI with force_update=True since properties changed
        self.update_data(force_update=True)

        # Show confirmation
        QMessageBox.information(
            self,
            "Application Added",
            f"The application '{os.path.basename(file_path)}' has been added to the list."
        )
