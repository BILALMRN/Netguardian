"""
Dashboard Widget Module for NetGuardian

This module provides the dashboard widget for the main window.
"""

import logging
import time
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QFrame, QAbstractItemView
)
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot, QTimer

import pyqtgraph as pg

from ..monitoring.connections import ConnectionMonitor
from ..monitoring.traffic import TrafficMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DashboardWidget(QWidget):
    """
    Widget for displaying the monitoring dashboard.
    """

    def __init__(self, connection_monitor: ConnectionMonitor, traffic_monitor: TrafficMonitor):
        """
        Initialize the dashboard widget.

        Args:
            connection_monitor: Connection monitor instance.
            traffic_monitor: Traffic monitor instance.
        """
        super().__init__()

        self.connection_monitor = connection_monitor
        self.traffic_monitor = traffic_monitor

        # Set up the UI
        self._setup_ui()

        # Load initial data
        self.update_data()

    def _setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create splitter for top and bottom sections
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Create top section (traffic graph)
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)

        # Traffic graph title
        graph_title = QLabel("Network Traffic")
        graph_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        graph_title_font = QFont()
        graph_title_font.setPointSize(12)
        graph_title_font.setBold(True)
        graph_title.setFont(graph_title_font)
        top_layout.addWidget(graph_title)

        # Create traffic graph
        self.traffic_graph = pg.PlotWidget()
        self.traffic_graph.setBackground('w')
        self.traffic_graph.setLabel('left', 'Traffic', units='B/s')
        self.traffic_graph.setLabel('bottom', 'Time', units='s')
        self.traffic_graph.showGrid(x=True, y=True)
        self.traffic_graph.setYRange(0, 1024 * 1024)  # 1 MB/s initial range

        # Create plot items
        self.upload_curve = self.traffic_graph.plot(pen=pg.mkPen(color='r', width=2), name="Upload")
        self.download_curve = self.traffic_graph.plot(pen=pg.mkPen(color='b', width=2), name="Download")

        # Add legend
        legend = self.traffic_graph.addLegend()

        top_layout.addWidget(self.traffic_graph)

        # Create traffic stats layout
        stats_layout = QHBoxLayout()

        # Current rates
        self.current_label = QLabel()
        stats_layout.addWidget(self.current_label)

        stats_layout.addStretch()

        # Average rates
        self.average_label = QLabel()
        stats_layout.addWidget(self.average_label)

        stats_layout.addStretch()

        # Peak rates
        self.peak_label = QLabel()
        stats_layout.addWidget(self.peak_label)

        top_layout.addLayout(stats_layout)

        # Create bottom section (connections table)
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        # Connections table title
        table_title = QLabel("Active Connections (Top 10 Most Active)")
        table_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        table_title_font = QFont()
        table_title_font.setPointSize(12)
        table_title_font.setBold(True)
        table_title.setFont(table_title_font)
        bottom_layout.addWidget(table_title)

        # Create connections table
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(6)
        self.connections_table.setHorizontalHeaderLabels([
            "Process", "PID", "Local Address", "Remote Address",
            "Type", "Status"
        ])
        self.connections_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.connections_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.connections_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.connections_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.connections_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.connections_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.connections_table.verticalHeader().setVisible(False)
        self.connections_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.connections_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        bottom_layout.addWidget(self.connections_table)

        # Add widgets to splitter
        splitter.addWidget(top_widget)
        splitter.addWidget(bottom_widget)

        # Set initial sizes
        splitter.setSizes([int(self.height() * 0.4), int(self.height() * 0.6)])

        # Add splitter to main layout
        main_layout.addWidget(splitter)

    def update_data(self, force_update=True):
        """
        Update the dashboard with current data.

        Args:
            force_update: Whether to force an update even if no properties changed.
                          Dashboard always updates since it shows real-time data.
        """
        # Dashboard always updates since it shows real-time data
        # Update traffic graph
        self._update_traffic_graph()

        # Update connections table
        self._update_connections_table()

    def _update_traffic_graph(self):
        """Update the traffic graph with current data."""
        # Get traffic history
        history = self.traffic_monitor.get_history()

        # Calculate relative timestamps
        now = time.time()
        relative_timestamps = [t - now for t in history["timestamps"]]

        # Update curves
        self.upload_curve.setData(relative_timestamps, history["send_rates"])
        self.download_curve.setData(relative_timestamps, history["recv_rates"])

        # Auto-scale Y axis based on peak traffic
        max_traffic = max(
            max(history["send_rates"]) if history["send_rates"] else 0,
            max(history["recv_rates"]) if history["recv_rates"] else 0
        )

        if max_traffic > 0:
            # Add 20% headroom
            max_traffic *= 1.2

            # Round to nice number
            if max_traffic < 1024:  # Less than 1 KB/s
                max_traffic = 1024  # Set minimum to 1 KB/s
            elif max_traffic < 1024 * 1024:  # Less than 1 MB/s
                max_traffic = ((max_traffic // 1024) + 1) * 1024  # Round up to next KB/s
            else:  # More than 1 MB/s
                max_traffic = ((max_traffic // (1024 * 1024)) + 1) * 1024 * 1024  # Round up to next MB/s

            self.traffic_graph.setYRange(0, max_traffic)

        # Update stats labels
        current_rates = self.traffic_monitor.get_current_rates()
        self.current_label.setText(
            f"Current: ↑ {self._format_bytes(current_rates['send_rate'])}/s | "
            f"↓ {self._format_bytes(current_rates['recv_rate'])}/s"
        )

        avg_rates = self.traffic_monitor.get_average_rates(30)  # 30 second average
        self.average_label.setText(
            f"Average (30s): ↑ {self._format_bytes(avg_rates['send_rate_avg'])}/s | "
            f"↓ {self._format_bytes(avg_rates['recv_rate_avg'])}/s"
        )

        peak_rates = self.traffic_monitor.get_peak_rates(60)  # 60 second peak
        self.peak_label.setText(
            f"Peak (60s): ↑ {self._format_bytes(peak_rates['send_rate_peak'])}/s | "
            f"↓ {self._format_bytes(peak_rates['recv_rate_peak'])}/s"
        )

    def _update_connections_table(self):
        """Update the connections table with current data."""
        # Get all connections
        connections = self.connection_monitor.get_all_connections()

        # Sort by traffic (send_rate + recv_rate) to show most active connections first
        connections.sort(key=lambda c: c["send_rate"] + c["recv_rate"], reverse=True)

        # Limit to top 10 active connections to prevent app crashes
        connections = connections[:10]

        # Update table
        self.connections_table.setRowCount(len(connections))

        for row, conn in enumerate(connections):
            # Process name
            process_item = QTableWidgetItem(conn["process_name"])
            self.connections_table.setItem(row, 0, process_item)

            # PID
            pid_item = QTableWidgetItem(str(conn["pid"]))
            self.connections_table.setItem(row, 1, pid_item)

            # Local address
            local_addr_item = QTableWidgetItem(conn["local_addr"])
            self.connections_table.setItem(row, 2, local_addr_item)

            # Remote address
            remote_addr_item = QTableWidgetItem(conn["remote_addr"])
            self.connections_table.setItem(row, 3, remote_addr_item)

            # Type
            type_item = QTableWidgetItem(conn["type"])
            self.connections_table.setItem(row, 4, type_item)

            # Status
            status_item = QTableWidgetItem(conn["status"])
            self.connections_table.setItem(row, 5, status_item)

            # # Traffic
            # traffic_text = f"↑ {self._format_bytes(conn['send_rate'])}/s | ↓ {self._format_bytes(conn['recv_rate'])}/s"
            # traffic_item = QTableWidgetItem(traffic_text)
            # self.connections_table.setItem(row, 6, traffic_item)

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
