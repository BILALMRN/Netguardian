"""
Connections Monitoring Module for NetGuardian

This module provides functionality for monitoring active network connections
and tracking connection statistics.
"""

import psutil
import time
import logging
import os
import socket
import threading
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Connection:
    """
    Represents a network connection.
    """

    def __init__(self,
                pid: int,
                process_name: str,
                local_addr: Tuple[str, int],
                remote_addr: Tuple[str, int],
                status: str,
                type: str):
        """
        Initialize a connection.

        Args:
            pid: Process ID.
            process_name: Name of the process.
            local_addr: Local address (IP, port).
            remote_addr: Remote address (IP, port).
            status: Connection status.
            type: Connection type (TCP, UDP).
        """
        self.pid = pid
        self.process_name = process_name
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.status = status
        self.type = type
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.prev_bytes_sent = 0
        self.prev_bytes_recv = 0
        self.send_rate = 0  # bytes per second
        self.recv_rate = 0  # bytes per second

        # Daily traffic statistics (reset at midnight)
        self.daily_bytes_sent = 0
        self.daily_bytes_recv = 0
        self.daily_start_time = self._get_start_of_day()

    def _get_start_of_day(self) -> float:
        """
        Get the timestamp for the start of the current day (00:00).

        Returns:
            Timestamp for midnight (00:00) of the current day.
        """
        now = time.localtime()
        day_start = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, 0))
        return day_start

    def update_traffic(self, bytes_sent: int, bytes_recv: int) -> None:
        """
        Update traffic statistics.

        Args:
            bytes_sent: Total bytes sent.
            bytes_recv: Total bytes received.
        """
        now = time.time()
        time_diff = now - self.last_seen

        # Check if we need to reset daily stats (new day)
        day_start = self._get_start_of_day()
        if day_start > self.daily_start_time:
            # It's a new day, reset daily stats
            self.daily_bytes_sent = 0
            self.daily_bytes_recv = 0
            self.daily_start_time = day_start

        if time_diff > 0:
            # Calculate rates
            self.send_rate = (bytes_sent - self.bytes_sent) / time_diff
            self.recv_rate = (bytes_recv - self.bytes_recv) / time_diff

            # Calculate bytes transferred since last update
            bytes_sent_diff = bytes_sent - self.bytes_sent
            bytes_recv_diff = bytes_recv - self.bytes_recv

            # Update daily totals if the difference is positive
            if bytes_sent_diff > 0:
                self.daily_bytes_sent += bytes_sent_diff
            if bytes_recv_diff > 0:
                self.daily_bytes_recv += bytes_recv_diff

            # Update totals
            self.prev_bytes_sent = self.bytes_sent
            self.prev_bytes_recv = self.bytes_recv
            self.bytes_sent = bytes_sent
            self.bytes_recv = bytes_recv
            self.last_seen = now

    def to_dict(self) -> Dict:
        """
        Convert the connection to a dictionary.

        Returns:
            Dictionary representation of the connection.
        """
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "local_addr": f"{self.local_addr[0]}:{self.local_addr[1]}",
            "remote_addr": f"{self.remote_addr[0]}:{self.remote_addr[1]}",
            "status": self.status,
            "type": self.type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "send_rate": self.send_rate,
            "recv_rate": self.recv_rate,
            "daily_bytes_sent": self.daily_bytes_sent,
            "daily_bytes_recv": self.daily_bytes_recv,
            "daily_start_time": self.daily_start_time
        }


class ConnectionMonitor:
    """
    Monitors network connections.
    """

    def __init__(self, update_interval: float = 1.0):
        """
        Initialize the connection monitor.

        Args:
            update_interval: Interval in seconds between updates.
        """
        self.update_interval = update_interval
        self.connections = {}  # key: (pid, laddr, raddr, type), value: Connection
        self.process_connections = defaultdict(set)  # key: pid, value: set of connection keys
        self.process_paths = {}  # key: pid, value: executable path
        self.running = False
        self.monitor_thread = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start monitoring connections."""
        if self.running:
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("Connection monitoring started")

    def stop(self) -> None:
        """Stop monitoring connections."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
        logger.info("Connection monitoring stopped")

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.running:
            try:
                self._update_connections()
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in connection monitoring: {e}")
                time.sleep(1.0)  # Sleep a bit to avoid tight loop on error

    def _update_connections(self) -> None:
        """Update the list of connections."""
        # Get all network connections
        connections = psutil.net_connections(kind='all')

        # Track active connection keys
        active_keys = set()

        # Update process paths
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                if proc.info['exe']:
                    self.process_paths[pid] = proc.info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Process each connection
        for conn in connections:
            try:
                if not conn.pid:
                    continue

                # Get process info
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = f"Unknown ({conn.pid})"

                # Create connection key
                laddr = conn.laddr if conn.laddr else ('0.0.0.0', 0)
                raddr = conn.raddr if conn.raddr else ('0.0.0.0', 0)
                conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                conn_key = (conn.pid, laddr, raddr, conn_type)

                # Mark as active
                active_keys.add(conn_key)

                with self._lock:
                    # Update or create connection
                    if conn_key in self.connections:
                        # Update existing connection
                        self.connections[conn_key].status = conn.status
                        self.connections[conn_key].last_seen = time.time()
                    else:
                        # Create new connection
                        self.connections[conn_key] = Connection(
                            pid=conn.pid,
                            process_name=process_name,
                            local_addr=laddr,
                            remote_addr=raddr,
                            status=conn.status,
                            type=conn_type
                        )
                        # Add to process connections
                        self.process_connections[conn.pid].add(conn_key)

                # Update traffic stats if possible
                try:
                    io_stats = proc.io_counters()
                    with self._lock:
                        if conn_key in self.connections:
                            self.connections[conn_key].update_traffic(
                                io_stats.write_bytes, io_stats.read_bytes
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    pass

            except Exception as e:
                logger.error(f"Error processing connection: {e}")

        # Remove inactive connections (older than 30 seconds)
        with self._lock:
            current_time = time.time()
            inactive_keys = []

            for key, conn in self.connections.items():
                if key not in active_keys and (current_time - conn.last_seen) > 30:
                    inactive_keys.append(key)

            # Remove inactive connections
            for key in inactive_keys:
                pid = key[0]
                if key in self.connections:
                    del self.connections[key]
                if pid in self.process_connections:
                    self.process_connections[pid].discard(key)
                    if not self.process_connections[pid]:
                        del self.process_connections[pid]

    def get_all_connections(self) -> List[Dict]:
        """
        Get all active connections.

        Returns:
            List of connection dictionaries.
        """
        with self._lock:
            return [conn.to_dict() for conn in self.connections.values()]

    def get_process_connections(self, pid: int) -> List[Dict]:
        """
        Get connections for a specific process.

        Args:
            pid: Process ID.

        Returns:
            List of connection dictionaries.
        """
        with self._lock:
            if pid in self.process_connections:
                return [self.connections[key].to_dict()
                        for key in self.process_connections[pid]
                        if key in self.connections]
            return []

    def get_app_connections(self, app_path: str) -> List[Dict]:
        """
        Get connections for a specific application.

        Args:
            app_path: Path to the application executable.

        Returns:
            List of connection dictionaries.
        """
        app_path = os.path.normpath(app_path).lower()

        with self._lock:
            # Find PIDs for the app
            pids = [pid for pid, path in self.process_paths.items()
                   if path and os.path.normpath(path).lower() == app_path]

            # Get connections for those PIDs
            connections = []
            for pid in pids:
                if pid in self.process_connections:
                    for key in self.process_connections[pid]:
                        if key in self.connections:
                            connections.append(self.connections[key].to_dict())

            return connections

    def get_total_traffic(self) -> Dict[str, float]:
        """
        Get total traffic statistics.

        Returns:
            Dictionary with total send and receive rates.
        """
        with self._lock:
            total_send_rate = sum(conn.send_rate for conn in self.connections.values())
            total_recv_rate = sum(conn.recv_rate for conn in self.connections.values())

            return {
                "send_rate": total_send_rate,
                "recv_rate": total_recv_rate
            }

    def get_app_traffic(self, app_path: str) -> Dict[str, float]:
        """
        Get traffic statistics for a specific application.

        Args:
            app_path: Path to the application executable.

        Returns:
            Dictionary with send and receive rates.
        """
        app_path = os.path.normpath(app_path).lower()

        with self._lock:
            # Find PIDs for the app
            pids = [pid for pid, path in self.process_paths.items()
                   if path and os.path.normpath(path).lower() == app_path]

            # Calculate total rates
            send_rate = 0
            recv_rate = 0

            for pid in pids:
                if pid in self.process_connections:
                    for key in self.process_connections[pid]:
                        if key in self.connections:
                            send_rate += self.connections[key].send_rate
                            recv_rate += self.connections[key].recv_rate

            return {
                "send_rate": send_rate,
                "recv_rate": recv_rate
            }

    def get_app_daily_traffic(self, app_path: str) -> Dict[str, float]:
        """
        Get daily traffic statistics for a specific application.

        Args:
            app_path: Path to the application executable.

        Returns:
            Dictionary with daily send and receive totals.
        """
        app_path = os.path.normpath(app_path).lower()

        with self._lock:
            # Find PIDs for the app
            pids = [pid for pid, path in self.process_paths.items()
                   if path and os.path.normpath(path).lower() == app_path]

            # Calculate daily totals
            daily_bytes_sent = 0
            daily_bytes_recv = 0

            for pid in pids:
                if pid in self.process_connections:
                    for key in self.process_connections[pid]:
                        if key in self.connections:
                            daily_bytes_sent += self.connections[key].daily_bytes_sent
                            daily_bytes_recv += self.connections[key].daily_bytes_recv

            return {
                "daily_bytes_sent": daily_bytes_sent,
                "daily_bytes_recv": daily_bytes_recv
            }
