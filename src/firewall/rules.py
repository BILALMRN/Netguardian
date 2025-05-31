"""
Firewall Rules Module for NetGuardian

This module provides functionality for managing firewall rules, including
creating, modifying, and scheduling rules.
"""

import json
import os
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Union
from threading import Timer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Rule:
    """
    Represents a firewall rule.
    """
    
    def __init__(self, 
                name: str, 
                program: Optional[str] = None,
                direction: str = "out",
                action: str = "block",
                protocol: str = "any",
                local_port: Optional[str] = None,
                remote_port: Optional[str] = None,
                local_ip: Optional[str] = None,
                remote_ip: Optional[str] = None,
                enabled: bool = True,
                schedule: Optional[Dict] = None):
        """
        Initialize a firewall rule.
        
        Args:
            name: Name of the rule.
            program: Optional path to the program.
            direction: 'in' or 'out'.
            action: 'allow' or 'block'.
            protocol: Protocol (TCP, UDP, any).
            local_port: Local port(s).
            remote_port: Remote port(s).
            local_ip: Local IP address(es).
            remote_ip: Remote IP address(es).
            enabled: Whether the rule is enabled.
            schedule: Optional schedule for the rule.
        """
        self.name = name
        self.program = program
        self.direction = direction
        self.action = action
        self.protocol = protocol
        self.local_port = local_port
        self.remote_port = remote_port
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.enabled = enabled
        self.schedule = schedule
        self.id = None  # Will be set when saved to database
        
    def to_dict(self) -> Dict:
        """
        Convert the rule to a dictionary.
        
        Returns:
            Dictionary representation of the rule.
        """
        return {
            "id": self.id,
            "name": self.name,
            "program": self.program,
            "direction": self.direction,
            "action": self.action,
            "protocol": self.protocol,
            "local_port": self.local_port,
            "remote_port": self.remote_port,
            "local_ip": self.local_ip,
            "remote_ip": self.remote_ip,
            "enabled": self.enabled,
            "schedule": self.schedule
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Rule':
        """
        Create a rule from a dictionary.
        
        Args:
            data: Dictionary containing rule data.
            
        Returns:
            Rule object.
        """
        rule = cls(
            name=data["name"],
            program=data.get("program"),
            direction=data.get("direction", "out"),
            action=data.get("action", "block"),
            protocol=data.get("protocol", "any"),
            local_port=data.get("local_port"),
            remote_port=data.get("remote_port"),
            local_ip=data.get("local_ip"),
            remote_ip=data.get("remote_ip"),
            enabled=data.get("enabled", True),
            schedule=data.get("schedule")
        )
        rule.id = data.get("id")
        return rule


class RuleManager:
    """
    Manages firewall rules, including persistence and scheduling.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the RuleManager.
        
        Args:
            db_path: Path to the SQLite database.
        """
        self.db_path = db_path
        self._init_db()
        self._scheduled_timers = {}
        self._load_scheduled_rules()
        
    def _init_db(self) -> None:
        """Initialize the database."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create rules table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            program TEXT,
            direction TEXT NOT NULL,
            action TEXT NOT NULL,
            protocol TEXT NOT NULL,
            local_port TEXT,
            remote_port TEXT,
            local_ip TEXT,
            remote_ip TEXT,
            enabled INTEGER NOT NULL,
            schedule TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def save_rule(self, rule: Rule) -> int:
        """
        Save a rule to the database.
        
        Args:
            rule: Rule to save.
            
        Returns:
            ID of the saved rule.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        schedule_json = json.dumps(rule.schedule) if rule.schedule else None
        
        if rule.id is None:
            # Insert new rule
            cursor.execute('''
            INSERT INTO rules (
                name, program, direction, action, protocol, 
                local_port, remote_port, local_ip, remote_ip, 
                enabled, schedule
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule.name, rule.program, rule.direction, rule.action, rule.protocol,
                rule.local_port, rule.remote_port, rule.local_ip, rule.remote_ip,
                1 if rule.enabled else 0, schedule_json
            ))
            rule.id = cursor.lastrowid
        else:
            # Update existing rule
            cursor.execute('''
            UPDATE rules SET
                name = ?, program = ?, direction = ?, action = ?, protocol = ?,
                local_port = ?, remote_port = ?, local_ip = ?, remote_ip = ?,
                enabled = ?, schedule = ?
            WHERE id = ?
            ''', (
                rule.name, rule.program, rule.direction, rule.action, rule.protocol,
                rule.local_port, rule.remote_port, rule.local_ip, rule.remote_ip,
                1 if rule.enabled else 0, schedule_json, rule.id
            ))
        
        conn.commit()
        conn.close()
        
        # Update scheduling if needed
        if rule.schedule and rule.enabled:
            self._schedule_rule(rule)
        elif rule.id in self._scheduled_timers:
            self._unschedule_rule(rule.id)
        
        return rule.id
    
    def get_rule(self, rule_id: int) -> Optional[Rule]:
        """
        Get a rule by ID.
        
        Args:
            rule_id: ID of the rule.
            
        Returns:
            Rule object or None if not found.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM rules WHERE id = ?', (rule_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            rule_dict = dict(row)
            rule_dict["enabled"] = bool(rule_dict["enabled"])
            if rule_dict["schedule"]:
                rule_dict["schedule"] = json.loads(rule_dict["schedule"])
            return Rule.from_dict(rule_dict)
        
        return None
    
    def get_all_rules(self) -> List[Rule]:
        """
        Get all rules.
        
        Returns:
            List of Rule objects.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM rules')
        rows = cursor.fetchall()
        
        conn.close()
        
        rules = []
        for row in rows:
            rule_dict = dict(row)
            rule_dict["enabled"] = bool(rule_dict["enabled"])
            if rule_dict["schedule"]:
                rule_dict["schedule"] = json.loads(rule_dict["schedule"])
            rules.append(Rule.from_dict(rule_dict))
        
        return rules
    
    def delete_rule(self, rule_id: int) -> bool:
        """
        Delete a rule.
        
        Args:
            rule_id: ID of the rule to delete.
            
        Returns:
            True if successful, False otherwise.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        
        conn.commit()
        conn.close()
        
        # Unschedule if needed
        if rule_id in self._scheduled_timers:
            self._unschedule_rule(rule_id)
        
        return True
    
    def _load_scheduled_rules(self) -> None:
        """Load and schedule all rules with schedules."""
        rules = self.get_all_rules()
        
        for rule in rules:
            if rule.schedule and rule.enabled:
                self._schedule_rule(rule)
    
    def _schedule_rule(self, rule: Rule) -> None:
        """
        Schedule a rule.
        
        Args:
            rule: Rule to schedule.
        """
        if not rule.schedule:
            return
        
        # Unschedule if already scheduled
        if rule.id in self._scheduled_timers:
            self._unschedule_rule(rule.id)
        
        schedule = rule.schedule
        
        # Schedule start time
        if "start_time" in schedule:
            start_time = self._parse_schedule_time(schedule["start_time"])
            if start_time > 0:
                timer = Timer(start_time, self._toggle_rule_state, args=(rule.id, True))
                timer.daemon = True
                timer.start()
                self._scheduled_timers[f"{rule.id}_start"] = timer
        
        # Schedule end time
        if "end_time" in schedule:
            end_time = self._parse_schedule_time(schedule["end_time"])
            if end_time > 0:
                timer = Timer(end_time, self._toggle_rule_state, args=(rule.id, False))
                timer.daemon = True
                timer.start()
                self._scheduled_timers[f"{rule.id}_end"] = timer
    
    def _unschedule_rule(self, rule_id: int) -> None:
        """
        Unschedule a rule.
        
        Args:
            rule_id: ID of the rule to unschedule.
        """
        start_key = f"{rule_id}_start"
        end_key = f"{rule_id}_end"
        
        if start_key in self._scheduled_timers:
            self._scheduled_timers[start_key].cancel()
            del self._scheduled_timers[start_key]
        
        if end_key in self._scheduled_timers:
            self._scheduled_timers[end_key].cancel()
            del self._scheduled_timers[end_key]
    
    def _toggle_rule_state(self, rule_id: int, enabled: bool) -> None:
        """
        Toggle a rule's enabled state.
        
        Args:
            rule_id: ID of the rule.
            enabled: New enabled state.
        """
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = enabled
            self.save_rule(rule)
            
            # Reschedule for the next day if this is a daily schedule
            if rule.schedule and rule.schedule.get("repeat") == "daily":
                self._schedule_rule(rule)
    
    def _parse_schedule_time(self, time_str: str) -> float:
        """
        Parse a schedule time string and return seconds until that time.
        
        Args:
            time_str: Time string in HH:MM format.
            
        Returns:
            Seconds until the specified time.
        """
        try:
            now = datetime.now()
            hour, minute = map(int, time_str.split(':'))
            
            target_time = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            
            # If the time has already passed today, schedule for tomorrow
            if target_time <= now:
                target_time += timedelta(days=1)
            
            return (target_time - now).total_seconds()
        
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid schedule time format: {time_str}, {e}")
            return -1
