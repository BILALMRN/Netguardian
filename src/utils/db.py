"""
Database Utility Module for NetGuardian

This module provides functionality for managing the application database,
including storing settings and application states.
"""

import os
import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Database:
    """
    Manages the application database.
    """

    def __init__(self, db_path: str):
        """
        Initialize the database.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._connection = None
        self._settings_cache = {}  # Cache for settings
        self._apps_cache = {}      # Cache for apps
        self._init_db()

    def _get_connection(self):
        """Get a database connection."""
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path)
        return self._connection

    def _close_connection(self):
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _init_db(self) -> None:
        """Initialize the database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create settings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        ''')

        # Create apps table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS apps (
            path TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            publisher TEXT,
            icon_path TEXT,
            is_blocked INTEGER DEFAULT 0,
            last_updated TEXT
        )
        ''')

        # Create notifications table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_path TEXT,
            message TEXT,
            timestamp TEXT,
            is_read INTEGER DEFAULT 0
        )
        ''')

        conn.commit()
        conn.close()

    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value.

        Args:
            key: Setting key.
            default: Default value if setting doesn't exist.

        Returns:
            Setting value or default.
        """
        # Check cache first
        if key in self._settings_cache:
            return self._settings_cache[key]

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()

        if row:
            try:
                value = json.loads(row[0])
            except json.JSONDecodeError:
                value = row[0]

            # Cache the result
            self._settings_cache[key] = value
            return value

        return default

    def set_setting(self, key: str, value: Any) -> None:
        """
        Set a setting value.

        Args:
            key: Setting key.
            value: Setting value.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Store the original value in cache
        self._settings_cache[key] = value

        # Convert non-string values to JSON for storage
        if not isinstance(value, str):
            db_value = json.dumps(value)
        else:
            db_value = value

        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
            (key, db_value)
        )

        conn.commit()

    def get_all_settings(self) -> Dict[str, Any]:
        """
        Get all settings.

        Returns:
            Dictionary of all settings.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()

        conn.close()

        settings = {}
        for key, value in rows:
            try:
                settings[key] = json.loads(value)
            except json.JSONDecodeError:
                settings[key] = value

        return settings

    def save_app(self,
                path: str,
                name: str,
                description: Optional[str] = None,
                publisher: Optional[str] = None,
                icon_path: Optional[str] = None,
                is_blocked: bool = False) -> None:
        """
        Save application information.

        Args:
            path: Path to the application executable.
            name: Name of the application.
            description: Description of the application.
            publisher: Publisher of the application.
            icon_path: Path to the application icon.
            is_blocked: Whether the application is blocked.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT OR REPLACE INTO apps
            (path, name, description, publisher, icon_path, is_blocked, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ''',
            (path, name, description, publisher, icon_path, 1 if is_blocked else 0)
        )

        conn.commit()

        # Update cache
        self._apps_cache[path] = {
            'path': path,
            'name': name,
            'description': description,
            'publisher': publisher,
            'icon_path': icon_path,
            'is_blocked': is_blocked,
            'last_updated': 'now'  # Approximate value
        }

    def get_app(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Get application information.

        Args:
            path: Path to the application executable.

        Returns:
            Dictionary with application information or None if not found.
        """
        # Check cache first
        if path in self._apps_cache:
            return self._apps_cache[path]

        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM apps WHERE path = ?', (path,))
        row = cursor.fetchone()

        if row:
            app = dict(row)
            app['is_blocked'] = bool(app['is_blocked'])

            # Update cache
            self._apps_cache[path] = app
            return app

        return None

    def get_all_apps(self, use_cache: bool = True) -> List[Dict[str, Any]]:
        """
        Get all applications.

        Args:
            use_cache: Whether to use cached results if available.

        Returns:
            List of dictionaries with application information.
        """
        # Check if we have a cached result and should use it
        if use_cache and self._apps_cache:
            return list(self._apps_cache.values())

        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM apps ORDER BY name')
        rows = cursor.fetchall()

        # Clear the cache
        self._apps_cache = {}

        apps = []
        for row in rows:
            app = dict(row)
            app['is_blocked'] = bool(app['is_blocked'])
            apps.append(app)

            # Update the cache
            self._apps_cache[app['path']] = app

        return apps

    def set_app_blocked(self, path: str, blocked: bool) -> None:
        """
        Set whether an application is blocked.

        Args:
            path: Path to the application executable.
            blocked: Whether the application is blocked.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            'UPDATE apps SET is_blocked = ?, last_updated = datetime("now") WHERE path = ?',
            (1 if blocked else 0, path)
        )

        conn.commit()

        # Update cache if the app is in it
        if path in self._apps_cache:
            self._apps_cache[path]['is_blocked'] = blocked
            self._apps_cache[path]['last_updated'] = 'now'  # Approximate value

    def delete_app(self, path: str) -> None:
        """
        Delete an application.

        Args:
            path: Path to the application executable.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM apps WHERE path = ?', (path,))

        conn.commit()

        # Remove from cache if present
        if path in self._apps_cache:
            del self._apps_cache[path]

    def add_notification(self, app_path: str, message: str) -> int:
        """
        Add a notification.

        Args:
            app_path: Path to the application executable.
            message: Notification message.

        Returns:
            ID of the added notification.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO notifications
            (app_path, message, timestamp, is_read)
            VALUES (?, ?, datetime('now'), 0)
            ''',
            (app_path, message)
        )

        notification_id = cursor.lastrowid

        conn.commit()
        conn.close()

        return notification_id

    def get_notifications(self, unread_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get notifications.

        Args:
            unread_only: Whether to get only unread notifications.

        Returns:
            List of dictionaries with notification information.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if unread_only:
            cursor.execute(
                '''
                SELECT n.*, a.name as app_name
                FROM notifications n
                LEFT JOIN apps a ON n.app_path = a.path
                WHERE n.is_read = 0
                ORDER BY n.timestamp DESC
                '''
            )
        else:
            cursor.execute(
                '''
                SELECT n.*, a.name as app_name
                FROM notifications n
                LEFT JOIN apps a ON n.app_path = a.path
                ORDER BY n.timestamp DESC
                '''
            )

        rows = cursor.fetchall()

        conn.close()

        notifications = []
        for row in rows:
            notification = dict(row)
            notification['is_read'] = bool(notification['is_read'])
            notifications.append(notification)

        return notifications

    def mark_notification_read(self, notification_id: int) -> None:
        """
        Mark a notification as read.

        Args:
            notification_id: ID of the notification.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            'UPDATE notifications SET is_read = 1 WHERE id = ?',
            (notification_id,)
        )

        conn.commit()
        conn.close()

    def clear_notifications(self) -> None:
        """Clear all notifications."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM notifications')

        conn.commit()
        conn.close()
