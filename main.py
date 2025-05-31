"""
NetGuardian - Windows Internet Access Control Application

This is the main entry point for the NetGuardian application.
"""

import sys
import os
import logging
import ctypes
from PyQt6.QtWidgets import QApplication, QLabel
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

from src.ui.main_window import MainWindow
from src.utils.system import is_admin, run_as_admin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("netguardian.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Main application entry point."""
    # Check for administrator privileges
    if not is_admin():
        logger.warning("Application requires administrator privileges for full functionality.")
        # Always enforce admin privileges since they're required for firewall management
        try:
            # Restart as administrator
            run_as_admin(sys.executable, sys.argv)
            return
        except Exception as e:
            logger.error(f"Failed to restart as administrator: {e}")
            # Show error message
            ctypes.windll.user32.MessageBoxW(
                0,
                "NetGuardian requires administrator privileges to manage firewall rules.\n"
                "Please run the application as administrator.",
                "Administrator Privileges Required",
                0x10  # MB_ICONERROR
            )
            return

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("NetGuardian")
    app.setApplicationDisplayName("NetGuardian - Internet Access Control")

    # Set application icon
    # app.setWindowIcon(QIcon("assets/icon.png"))

    # Create splash screen
    splash_label = QLabel()
    splash_label.setWindowFlags(Qt.WindowType.SplashScreen | Qt.WindowType.FramelessWindowHint)
    splash_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    splash_label.setStyleSheet("""
        background-color: #2c3e50;
        color: white;
        font-size: 24px;
        padding: 40px;
        border-radius: 10px;
    """)
    splash_label.setText("Loading NetGuardian...\nPlease wait")
    splash_label.setFixedSize(400, 200)

    # Center splash screen
    screen_geometry = app.primaryScreen().geometry()
    x = (screen_geometry.width() - splash_label.width()) // 2
    y = (screen_geometry.height() - splash_label.height()) // 2
    splash_label.move(x, y)

    # Show splash screen
    splash_label.show()
    app.processEvents()

    # Create main window but don't show it yet
    main_window = MainWindow(splash_label)

    # Run application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
