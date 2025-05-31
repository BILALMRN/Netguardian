"""
Main Window Module for NetGuardian

This module provides the main application window.
"""

import os
import sys
import logging
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QTabWidget, QVBoxLayout, QHBoxLayout,
    QWidget, QLabel, QPushButton, QStatusBar, QMessageBox, QSystemTrayIcon,
    QMenu
)
from PyQt6.QtGui import QIcon, QPixmap, QAction, QFont
from PyQt6.QtCore import Qt, QSize, QTimer, pyqtSignal, QEvent, QThread

# Worker thread for monitoring services
class MonitorThread(QThread):
    """Worker thread for starting monitoring services."""

    # Signal for status updates
    status_update = pyqtSignal(str)

    def __init__(self, connection_monitor, traffic_monitor, app_detector):
        """Initialize the monitor thread."""
        super().__init__()
        self.connection_monitor = connection_monitor
        self.traffic_monitor = traffic_monitor
        self.app_detector = app_detector

    def run(self):
        """Run the thread."""
        # Start connection monitor
        self.status_update.emit("Starting connection monitor...")
        self.connection_monitor.start()

        # Small delay to avoid UI freezing
        self.msleep(500)

        # Start traffic monitor
        self.status_update.emit("Starting traffic monitor...")
        self.traffic_monitor.start()

        # Small delay to avoid UI freezing
        self.msleep(500)

        # Start app detector
        self.status_update.emit("Starting application detector...")
        self.app_detector.start()

        # Final status update
        self.status_update.emit("All monitoring services started")

from ..utils.system import is_admin, run_as_admin, get_app_data_dir
from ..firewall.manager import FirewallManager
from ..monitoring.connections import ConnectionMonitor
from ..monitoring.traffic import TrafficMonitor
from ..utils.app_detector import AppDetector
from ..utils.db import Database

# Import UI components
from .app_list import AppListWidget
from .dashboard import DashboardWidget
from .rules_editor import RulesEditorWidget
from .settings import SettingsWidget

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    """
    Main application window.
    """

    # Signal for new application detection
    new_app_detected = pyqtSignal(dict)

    def __init__(self, splash_screen=None):
        """Initialize the main window."""
        super().__init__()

        self.splash_screen = splash_screen
        self._update_splash("Initializing...")

        # Check for admin privileges
        self.has_admin = is_admin()
        if not self.has_admin:
            QMessageBox.warning(
                None,
                "Limited Functionality",
                "NetGuardian is running without administrator privileges.\n"
                "Firewall management features will be disabled.\n"
                "Please restart the application as administrator for full functionality."
            )

        # Initialize components (lightweight operations only)
        self._init_components()

        # Set up the UI
        self._update_splash("Setting up user interface...")
        self._setup_ui()

        # Connect signals and slots
        self._connect_signals()

        # Show the window before starting heavy operations
        self.show()
        QApplication.processEvents()

        # Start monitoring in a separate thread
        self._update_splash("Starting monitoring services...")
        QTimer.singleShot(100, self._start_monitoring)

    def _update_splash(self, message):
        """Update splash screen message if available."""
        if self.splash_screen:
            self.splash_screen.setText(f"Loading NetGuardian...\n{message}")
            QApplication.processEvents()

    def _init_components(self):
        """Initialize application components."""
        # Get application data directory
        self.app_data_dir = get_app_data_dir("NetGuardian")

        # Initialize database
        db_path = os.path.join(self.app_data_dir, "netguardian.db")
        self.db = Database(db_path)

        # Initialize firewall manager
        self.firewall_manager = FirewallManager()

        # Initialize connection monitor
        self.connection_monitor = ConnectionMonitor()

        # Initialize traffic monitor
        self.traffic_monitor = TrafficMonitor()

        # Initialize app detector
        self.app_detector = AppDetector()

        # Register callback for new app detection
        self.app_detector.register_new_app_callback(self._on_new_app_detected)

    def _setup_ui(self):
        """Set up the user interface."""
        # Set window properties
        self.setWindowTitle("NetGuardian - Internet Access Control")
        self.setMinimumSize(900, 600)

        # Set window icon
        # self.setWindowIcon(QIcon("assets/icon.png"))

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Create header
        header_layout = QHBoxLayout()

        # Logo and title
        # logo_label = QLabel()
        # logo_pixmap = QPixmap("assets/logo.png")
        # logo_label.setPixmap(logo_pixmap.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio))
        # header_layout.addWidget(logo_label)

        title_label = QLabel("NetGuardian")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Add header to main layout
        main_layout.addLayout(header_layout)

        # Create tab widget
        self.tab_widget = QTabWidget()

        # Create tabs
        self.app_list_widget = AppListWidget(self.firewall_manager, self.db, self.connection_monitor)
        self.dashboard_widget = DashboardWidget(self.connection_monitor, self.traffic_monitor)
        self.rules_editor_widget = RulesEditorWidget(self.firewall_manager, self.db)
        self.settings_widget = SettingsWidget(self.db)

        # Add tabs to tab widget
        self.tab_widget.addTab(self.app_list_widget, "Applications")
        self.tab_widget.addTab(self.dashboard_widget, "Dashboard")
        self.tab_widget.addTab(self.rules_editor_widget, "Rules")
        self.tab_widget.addTab(self.settings_widget, "Settings")

        # Add tab widget to main layout
        main_layout.addWidget(self.tab_widget)

        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Add status indicators
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        # Create system tray icon
        self._setup_tray_icon()

    def _setup_tray_icon(self):
        """Set up the system tray icon."""
        self.tray_icon = QSystemTrayIcon(self)
        # self.tray_icon.setIcon(QIcon("assets/icon.png"))

        # Create tray menu
        tray_menu = QMenu()

        # Add actions
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)

        tray_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)

        # Set tray menu
        self.tray_icon.setContextMenu(tray_menu)

        # Show tray icon
        self.tray_icon.show()

        # Connect signals
        self.tray_icon.activated.connect(self._on_tray_icon_activated)

    def _connect_signals(self):
        """Connect signals and slots."""
        # Connect new app detected signal
        self.new_app_detected.connect(self._handle_new_app)

        # Connect tab changed signal
        self.tab_widget.currentChanged.connect(self._on_tab_changed)

    def _start_monitoring(self):
        """Start monitoring services."""
        # Hide splash screen if it exists
        if self.splash_screen:
            self.splash_screen.hide()
            self.splash_screen = None

        # Set up update timer for UI with a slower refresh rate
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_ui)
        self.update_timer.start(3000)  # Update every 3 seconds for better performance

        # Create a worker thread for monitoring services
        self.monitor_thread = MonitorThread(
            self.connection_monitor,
            self.traffic_monitor,
            self.app_detector
        )

        # Connect signals
        self.monitor_thread.status_update.connect(self._handle_status_update)
        self.monitor_thread.finished.connect(self._handle_monitor_thread_finished)

        # Start the thread
        self.monitor_thread.start()

        # Show status message
        self.status_label.setText("Starting monitoring services...")

    def _handle_status_update(self, message):
        """Handle status update from monitor thread."""
        self.status_label.setText(message)

    def _handle_monitor_thread_finished(self):
        """Handle monitor thread finished."""
        self.status_label.setText("Ready")

        # Update UI once after all services are started
        self._update_ui()

    def _update_ui(self, force_update=False):
        """
        Update the UI with current data.

        Args:
            force_update: Whether to force an update even if no properties changed.
        """
        try:
            # Only update the dashboard tab automatically
            current_tab = self.tab_widget.currentWidget()

            # NEVER update the app list tab during regular timer updates
            # This prevents the infinite reloading issue
            if current_tab == self.app_list_widget:
                # Skip app list updates completely during regular timer updates
                pass
            elif current_tab == self.dashboard_widget and hasattr(current_tab, "update_data"):
                # Dashboard should always update since it shows real-time data
                current_tab.update_data(force_update=True)
            elif hasattr(current_tab, "update_data") and force_update:
                # Other tabs only update when properties change or force_update is True
                current_tab.update_data(force_update=force_update)

            # Always update status bar with traffic info
            try:
                traffic = self.traffic_monitor.get_current_rates()
                upload_rate = self._format_bytes(traffic["send_rate"]) + "/s"
                download_rate = self._format_bytes(traffic["recv_rate"]) + "/s"

                self.status_label.setText(f"Upload: {upload_rate} | Download: {download_rate}")
            except Exception as e:
                # Don't crash if traffic monitor isn't ready yet
                logger.debug(f"Error updating traffic stats: {e}")
        except Exception as e:
            # Catch any exceptions to prevent UI freezes
            logger.error(f"Error in UI update: {e}")

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

    def _on_tab_changed(self, index: int):
        """
        Handle tab changed event.

        Args:
            index: Index of the new tab.
        """
        # Update the current tab
        current_tab = self.tab_widget.widget(index)

        if current_tab == self.dashboard_widget and hasattr(current_tab, "update_data"):
            # Dashboard should always update since it shows real-time data
            current_tab.update_data(force_update=True)
        elif current_tab == self.app_list_widget:
            # NEVER update the app list when changing tabs
            # The app list is loaded once at startup and only updates when properties change
            pass
        elif hasattr(current_tab, "update_data"):
            # Other tabs update normally
            current_tab.update_data()

    def _on_tray_icon_activated(self, reason):
        """
        Handle tray icon activation.

        Args:
            reason: Activation reason.
        """
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.activateWindow()

    def _on_new_app_detected(self, app_info):
        """
        Handle new application detection.

        Args:
            app_info: Application information.
        """
        # Emit signal to handle in the UI thread
        self.new_app_detected.emit(app_info.to_dict())

    def _handle_new_app(self, app_info: Dict[str, Any]):
        """
        Handle new application detection in the UI thread.

        Args:
            app_info: Application information.
        """
        # Check if notification is enabled
        if self.db.get_setting("notify_new_apps", True):
            # Add notification
            self.db.add_notification(
                app_info["path"],
                f"New application detected: {app_info['name']}"
            )

            # Show tray notification
            self.tray_icon.showMessage(
                "New Application Detected",
                f"NetGuardian detected a new application: {app_info['name']}",
                QSystemTrayIcon.MessageIcon.Information,
                5000  # 5 seconds
            )

        # Save app to database
        self.db.save_app(
            path=app_info["path"],
            name=app_info["name"],
            description=app_info.get("description"),
            publisher=app_info.get("publisher"),
            icon_path=app_info.get("icon_path"),
            is_blocked=False  # Default to allowed
        )

        # Update app list if it's the current tab
        if self.tab_widget.currentWidget() == self.app_list_widget:
            # Force update since a new app was added
            self.app_list_widget.update_data(force_update=True)

    def closeEvent(self, event):
        """
        Handle window close event.

        Args:
            event: Close event.
        """
        # Check if minimize to tray is enabled
        if self.db.get_setting("minimize_to_tray", True) and not self.isHidden():
            event.ignore()
            self.hide()

            # Show tray notification
            self.tray_icon.showMessage(
                "NetGuardian",
                "NetGuardian is still running in the background.",
                QSystemTrayIcon.MessageIcon.Information,
                3000  # 3 seconds
            )
        else:
            # Stop monitoring
            self.connection_monitor.stop()
            self.traffic_monitor.stop()
            self.app_detector.stop()

            # Accept the close event
            event.accept()
