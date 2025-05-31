"""
Rules Editor Widget Module for NetGuardian

This module provides the rules editor widget for the main window.
"""

import os
import logging
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QComboBox,
    QAbstractItemView, QMessageBox, QFileDialog, QDialog, QFormLayout,
    QTimeEdit, QGroupBox, QRadioButton, QButtonGroup
)
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot, QTime

from ..firewall.manager import FirewallManager
from ..firewall.rules import Rule, RuleManager
from ..utils.db import Database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RuleDialog(QDialog):
    """
    Dialog for creating or editing a firewall rule.
    """

    def __init__(self, parent=None, rule=None):
        """
        Initialize the rule dialog.

        Args:
            parent: Parent widget.
            rule: Optional rule to edit.
        """
        super().__init__(parent)

        self.rule = rule
        self.setWindowTitle("Edit Rule" if rule else "Create Rule")
        self.resize(500, 400)

        # Set up the UI
        self._setup_ui()

        # Load rule data if editing
        if rule:
            self._load_rule_data()

    def _setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        main_layout = QVBoxLayout(self)

        # Create form layout
        form_layout = QFormLayout()

        # Rule name
        self.name_input = QLineEdit()
        form_layout.addRow("Rule Name:", self.name_input)

        # Program path
        program_layout = QHBoxLayout()
        self.program_input = QLineEdit()
        program_layout.addWidget(self.program_input)

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self._browse_program)
        program_layout.addWidget(self.browse_button)

        form_layout.addRow("Program:", program_layout)

        # Direction
        self.direction_combo = QComboBox()
        self.direction_combo.addItem("Outbound", "out")
        self.direction_combo.addItem("Inbound", "in")
        form_layout.addRow("Direction:", self.direction_combo)

        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItem("Block", "block")
        self.action_combo.addItem("Allow", "allow")
        form_layout.addRow("Action:", self.action_combo)

        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("Any", "any")
        self.protocol_combo.addItem("TCP", "tcp")
        self.protocol_combo.addItem("UDP", "udp")
        self.protocol_combo.addItem("ICMP", "icmp")
        form_layout.addRow("Protocol:", self.protocol_combo)

        # Local port
        self.local_port_input = QLineEdit()
        self.local_port_input.setPlaceholderText("e.g., 80, 443, 1000-2000")
        form_layout.addRow("Local Port:", self.local_port_input)

        # Remote port
        self.remote_port_input = QLineEdit()
        self.remote_port_input.setPlaceholderText("e.g., 80, 443, 1000-2000")
        form_layout.addRow("Remote Port:", self.remote_port_input)

        # Local IP
        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("e.g., 192.168.1.1, 10.0.0.0/24")
        form_layout.addRow("Local IP:", self.local_ip_input)

        # Remote IP
        self.remote_ip_input = QLineEdit()
        self.remote_ip_input.setPlaceholderText("e.g., 8.8.8.8, 1.1.1.1")
        form_layout.addRow("Remote IP:", self.remote_ip_input)

        # Enabled
        self.enabled_checkbox = QCheckBox("Enabled")
        self.enabled_checkbox.setChecked(True)
        form_layout.addRow("", self.enabled_checkbox)

        # Add form layout to main layout
        main_layout.addLayout(form_layout)

        # Schedule group
        schedule_group = QGroupBox("Schedule")
        schedule_layout = QVBoxLayout(schedule_group)

        # Schedule type
        schedule_type_layout = QHBoxLayout()

        self.schedule_type_group = QButtonGroup(self)

        self.no_schedule_radio = QRadioButton("No Schedule")
        self.schedule_type_group.addButton(self.no_schedule_radio, 0)
        schedule_type_layout.addWidget(self.no_schedule_radio)

        self.one_time_radio = QRadioButton("One-time")
        self.schedule_type_group.addButton(self.one_time_radio, 1)
        schedule_type_layout.addWidget(self.one_time_radio)

        self.daily_radio = QRadioButton("Daily")
        self.schedule_type_group.addButton(self.daily_radio, 2)
        schedule_type_layout.addWidget(self.daily_radio)

        schedule_layout.addLayout(schedule_type_layout)

        # Schedule times
        schedule_times_layout = QFormLayout()

        self.start_time_edit = QTimeEdit()
        self.start_time_edit.setDisplayFormat("HH:mm")
        self.start_time_edit.setTime(QTime(9, 0))
        schedule_times_layout.addRow("Start Time:", self.start_time_edit)

        self.end_time_edit = QTimeEdit()
        self.end_time_edit.setDisplayFormat("HH:mm")
        self.end_time_edit.setTime(QTime(17, 0))
        schedule_times_layout.addRow("End Time:", self.end_time_edit)

        schedule_layout.addLayout(schedule_times_layout)

        # Connect schedule type change
        self.schedule_type_group.buttonClicked.connect(self._on_schedule_type_changed)

        # Set default
        self.no_schedule_radio.setChecked(True)
        self._on_schedule_type_changed()

        main_layout.addWidget(schedule_group)

        # Buttons
        buttons_layout = QHBoxLayout()

        buttons_layout.addStretch()

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self.cancel_button)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self._save_rule)
        buttons_layout.addWidget(self.save_button)

        main_layout.addLayout(buttons_layout)

    def _on_schedule_type_changed(self):
        """Handle schedule type change."""
        schedule_enabled = not self.no_schedule_radio.isChecked()

        self.start_time_edit.setEnabled(schedule_enabled)
        self.end_time_edit.setEnabled(schedule_enabled)

    def _browse_program(self):
        """Browse for a program executable."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Program",
            "",
            "Executable Files (*.exe)"
        )

        if file_path:
            self.program_input.setText(file_path)

    def _load_rule_data(self):
        """Load rule data into the form."""
        if not self.rule:
            return

        self.name_input.setText(self.rule.name)

        if self.rule.program:
            self.program_input.setText(self.rule.program)

        # Set direction
        index = self.direction_combo.findData(self.rule.direction)
        if index >= 0:
            self.direction_combo.setCurrentIndex(index)

        # Set action
        index = self.action_combo.findData(self.rule.action)
        if index >= 0:
            self.action_combo.setCurrentIndex(index)

        # Set protocol
        index = self.protocol_combo.findData(self.rule.protocol)
        if index >= 0:
            self.protocol_combo.setCurrentIndex(index)

        # Set ports and IPs
        if self.rule.local_port:
            self.local_port_input.setText(self.rule.local_port)

        if self.rule.remote_port:
            self.remote_port_input.setText(self.rule.remote_port)

        if self.rule.local_ip:
            self.local_ip_input.setText(self.rule.local_ip)

        if self.rule.remote_ip:
            self.remote_ip_input.setText(self.rule.remote_ip)

        # Set enabled
        self.enabled_checkbox.setChecked(self.rule.enabled)

        # Set schedule
        if self.rule.schedule:
            if self.rule.schedule.get("repeat") == "daily":
                self.daily_radio.setChecked(True)
            else:
                self.one_time_radio.setChecked(True)

            if "start_time" in self.rule.schedule:
                hours, minutes = map(int, self.rule.schedule["start_time"].split(":"))
                self.start_time_edit.setTime(QTime(hours, minutes))

            if "end_time" in self.rule.schedule:
                hours, minutes = map(int, self.rule.schedule["end_time"].split(":"))
                self.end_time_edit.setTime(QTime(hours, minutes))
        else:
            self.no_schedule_radio.setChecked(True)

        self._on_schedule_type_changed()

    def _save_rule(self):
        """Save the rule."""
        # Validate inputs
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Validation Error", "Rule name is required.")
            return

        # Get values
        program = self.program_input.text().strip()
        direction = self.direction_combo.currentData()
        action = self.action_combo.currentData()
        protocol = self.protocol_combo.currentData()
        local_port = self.local_port_input.text().strip()
        remote_port = self.remote_port_input.text().strip()
        local_ip = self.local_ip_input.text().strip()
        remote_ip = self.remote_ip_input.text().strip()
        enabled = self.enabled_checkbox.isChecked()

        # Get schedule
        schedule = None
        if not self.no_schedule_radio.isChecked():
            schedule = {}

            if self.daily_radio.isChecked():
                schedule["repeat"] = "daily"

            start_time = self.start_time_edit.time()
            schedule["start_time"] = f"{start_time.hour():02d}:{start_time.minute():02d}"

            end_time = self.end_time_edit.time()
            schedule["end_time"] = f"{end_time.hour():02d}:{end_time.minute():02d}"

        # Create or update rule
        if self.rule:
            # Update existing rule
            self.rule.name = name
            self.rule.program = program if program else None
            self.rule.direction = direction
            self.rule.action = action
            self.rule.protocol = protocol
            self.rule.local_port = local_port if local_port else None
            self.rule.remote_port = remote_port if remote_port else None
            self.rule.local_ip = local_ip if local_ip else None
            self.rule.remote_ip = remote_ip if remote_ip else None
            self.rule.enabled = enabled
            self.rule.schedule = schedule
        else:
            # Create new rule
            self.rule = Rule(
                name=name,
                program=program if program else None,
                direction=direction,
                action=action,
                protocol=protocol,
                local_port=local_port if local_port else None,
                remote_port=remote_port if remote_port else None,
                local_ip=local_ip if local_ip else None,
                remote_ip=remote_ip if remote_ip else None,
                enabled=enabled,
                schedule=schedule
            )

        # Accept dialog
        self.accept()

    def get_rule(self) -> Optional[Rule]:
        """
        Get the rule.

        Returns:
            Rule object or None if canceled.
        """
        return self.rule


class RulesEditorWidget(QWidget):
    """
    Widget for editing firewall rules.
    """

    def __init__(self, firewall_manager: FirewallManager, db: Database):
        """
        Initialize the rules editor widget.

        Args:
            firewall_manager: Firewall manager instance.
            db: Database instance.
        """
        super().__init__()

        self.firewall_manager = firewall_manager
        self.db = db

        # Create rule manager
        rule_db_path = os.path.join(os.path.dirname(self.db.db_path), "rules.db")
        self.rule_manager = RuleManager(rule_db_path)

        # Set up the UI
        self._setup_ui()

        # Load initial data
        self.update_data()

    def _setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create toolbar
        toolbar_layout = QHBoxLayout()

        # Add rule button
        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.clicked.connect(self._add_rule)
        toolbar_layout.addWidget(self.add_rule_button)

        # Filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter rules...")
        self.filter_input.textChanged.connect(self._filter_rules)
        toolbar_layout.addWidget(self.filter_input)

        # Add toolbar to main layout
        main_layout.addLayout(toolbar_layout)

        # Create rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(7)
        self.rules_table.setHorizontalHeaderLabels([
            "Name", "Program", "Direction", "Action", "Protocol", "Enabled", "Actions"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        # Add table to main layout
        main_layout.addWidget(self.rules_table)

    def update_data(self, force_update=False):
        """
        Update the rules list with current data.

        Args:
            force_update: Whether to force an update even if no properties changed.
        """
        # Only update when properties change or force_update is True
        if force_update:
            # Get all rules
            rules = self.rule_manager.get_all_rules()

            # Apply filter
            self._filter_rules()

    def _filter_rules(self):
        """Filter the rules list based on search criteria."""
        # Get all rules
        rules = self.rule_manager.get_all_rules()

        # Get filter text
        filter_text = self.filter_input.text().lower()

        # Filter rules
        filtered_rules = []
        for rule in rules:
            # Apply filter
            if filter_text:
                if (filter_text not in rule.name.lower() and
                    (not rule.program or filter_text not in rule.program.lower())):
                    continue

            filtered_rules.append(rule)

        # Update table
        self._update_table(filtered_rules)

    def _update_table(self, rules: List[Rule]):
        """
        Update the table with the given rules.

        Args:
            rules: List of Rule objects.
        """
        # Clear table
        self.rules_table.setRowCount(0)

        # Add rules to table
        for row, rule in enumerate(rules):
            self.rules_table.insertRow(row)

            # Name
            name_item = QTableWidgetItem(rule.name)
            self.rules_table.setItem(row, 0, name_item)

            # Program
            program_item = QTableWidgetItem(rule.program if rule.program else "Any")
            self.rules_table.setItem(row, 1, program_item)

            # Direction
            direction_text = "Outbound" if rule.direction == "out" else "Inbound"
            direction_item = QTableWidgetItem(direction_text)
            self.rules_table.setItem(row, 2, direction_item)

            # Action
            action_text = "Block" if rule.action == "block" else "Allow"
            action_item = QTableWidgetItem(action_text)
            action_item.setForeground(
                QColor(255, 0, 0) if rule.action == "block" else QColor(0, 128, 0)
            )
            self.rules_table.setItem(row, 3, action_item)

            # Protocol
            protocol_item = QTableWidgetItem(rule.protocol.upper())
            self.rules_table.setItem(row, 4, protocol_item)

            # Enabled
            enabled_item = QTableWidgetItem("Yes" if rule.enabled else "No")
            self.rules_table.setItem(row, 5, enabled_item)

            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)

            # Edit button
            edit_button = QPushButton("Edit")
            edit_button.clicked.connect(lambda checked, r=rule: self._edit_rule(r))
            actions_layout.addWidget(edit_button)

            # Delete button
            delete_button = QPushButton("Delete")
            delete_button.clicked.connect(lambda checked, r=rule: self._delete_rule(r))
            actions_layout.addWidget(delete_button)

            self.rules_table.setCellWidget(row, 6, actions_widget)

    def _add_rule(self):
        """Add a new rule."""
        dialog = RuleDialog(self)
        result = dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            rule = dialog.get_rule()
            if rule:
                # Save rule to database
                self.rule_manager.save_rule(rule)

                # Apply rule to firewall
                self._apply_rule(rule)

                # Update UI with force_update=True since properties changed
                self.update_data(force_update=True)

    def _edit_rule(self, rule: Rule):
        """
        Edit a rule.

        Args:
            rule: Rule to edit.
        """
        dialog = RuleDialog(self, rule)
        result = dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            # Save rule to database
            self.rule_manager.save_rule(rule)

            # Apply rule to firewall
            self._apply_rule(rule)

            # Update UI with force_update=True since properties changed
            self.update_data(force_update=True)

    def _delete_rule(self, rule: Rule):
        """
        Delete a rule.

        Args:
            rule: Rule to delete.
        """
        # Confirm deletion
        result = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the rule '{rule.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        # Delete rule from firewall
        self.firewall_manager.delete_rule(rule.name)

        # Delete rule from database
        self.rule_manager.delete_rule(rule.id)

        # Update UI with force_update=True since properties changed
        self.update_data(force_update=True)

    def _apply_rule(self, rule: Rule):
        """
        Apply a rule to the firewall.

        Args:
            rule: Rule to apply.
        """
        if not rule.enabled:
            # Delete rule from firewall if it exists
            self.firewall_manager.delete_rule(rule.name)
            return

        # Create or update rule in firewall
        self.firewall_manager.create_custom_rule(
            name=rule.name,
            program=rule.program,
            direction=rule.direction,
            action=rule.action,
            protocol=rule.protocol,
            local_port=rule.local_port,
            remote_port=rule.remote_port,
            local_ip=rule.local_ip,
            remote_ip=rule.remote_ip
        )
