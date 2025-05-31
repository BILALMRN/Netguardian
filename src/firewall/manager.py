"""
Firewall Manager Module for NetGuardian

This module provides the core functionality for interacting with the Windows Firewall.
It uses the netsh advfirewall commands to create, modify, and delete firewall rules.
"""

import subprocess
import logging
import os
import sys
from typing import List, Dict, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Manages Windows Firewall rules for applications.
    """

    def __init__(self):
        """Initialize the FirewallManager."""
        self.has_admin = self._verify_admin_privileges()

    def _verify_admin_privileges(self) -> bool:
        """
        Verify that the application is running with administrator privileges.

        Returns:
            True if running with admin privileges, False otherwise.
        """
        try:
            # This command will fail if not running as admin
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Admin privileges verified")
            return True
        except subprocess.CalledProcessError:
            logger.warning("Application is running without administrator privileges. Firewall management will be disabled.")
            return False

    def get_all_rules(self) -> List[Dict[str, str]]:
        """
        Get all firewall rules.

        Returns:
            List of dictionaries containing rule information.
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True,
                text=True,
                check=True
            )

            # Parse the output to extract rule information
            rules = []
            current_rule = {}

            for line in result.stdout.splitlines():
                line = line.strip()

                # New rule starts with "Rule Name:"
                if line.startswith("Rule Name:"):
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {}
                    current_rule["name"] = line.split(":", 1)[1].strip()
                elif ":" in line:
                    key, value = line.split(":", 1)
                    current_rule[key.strip().lower()] = value.strip()

            # Add the last rule
            if current_rule:
                rules.append(current_rule)

            return rules

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    def get_app_rules(self, app_path: str) -> List[Dict[str, str]]:
        """
        Get firewall rules for a specific application.

        Args:
            app_path: Path to the application executable.

        Returns:
            List of dictionaries containing rule information.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot get app rules: No administrator privileges")
            return []

        try:
            # Use verbose output for more detailed rule information
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"program={app_path}", "verbose"],
                capture_output=True,
                text=True,
                check=True
            )

            # Check if no rules were found
            if "No rules match the specified criteria" in result.stdout:
                logger.debug(f"No firewall rules found for {app_path}")
                return []

            # Parse the output to extract rule information
            rules = []
            current_rule = {}

            for line in result.stdout.splitlines():
                line = line.strip()

                # New rule starts with "Rule Name:"
                if line.startswith("Rule Name:"):
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {}
                    current_rule["name"] = line.split(":", 1)[1].strip()
                elif ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    # Store important rule properties
                    if "enabled" in key:
                        current_rule["enabled"] = value.lower() == "yes"
                    elif "direction" in key:
                        current_rule["dir"] = value.lower()
                    elif "action" in key:
                        current_rule["action"] = value.lower()
                    elif "program" in key:
                        current_rule["program"] = value
                    else:
                        # Store other properties
                        current_rule[key] = value

            # Add the last rule
            if current_rule:
                rules.append(current_rule)

            logger.debug(f"Found {len(rules)} firewall rules for {app_path}")
            return rules

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get firewall rules for {app_path}: {e}")
            logger.error(f"Command output: {e.stderr}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting rules for {app_path}: {e}")
            return []

    def enable_rule(self, rule_name: str) -> bool:
        """
        Enable a firewall rule.
        Args:
            rule_name: Name of the rule to enable.
        Returns:
            True if successful, False otherwise.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot enable rule: No administrator privileges")
            return False

        try:
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "set", "rule",
                f"name={rule_name}",
                "new",
                "enable=yes"
            ], capture_output=True, text=True, check=True)

            logger.info(f"Successfully enabled rule: {rule_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable rule {rule_name}: {e}")
            logger.error(f"Command output: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error enabling rule {rule_name}: {e}")
            return False

    def disable_rule(self, rule_name: str) -> bool:
        """
        Disable a firewall rule.
        Args:
            rule_name: Name of the rule to disable.
        Returns:
            True if successful, False otherwise.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot disable rule: No administrator privileges")
            return False

        try:
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "set", "rule",
                f"name={rule_name}",
                "new",
                "enable=no"
            ], capture_output=True, text=True, check=True)

            logger.info(f"Successfully disabled rule: {rule_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable rule {rule_name}: {e}")
            logger.error(f"Command output: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error disabling rule {rule_name}: {e}")
            return False

    def block_app(self, app_path: str, rule_name: Optional[str] = None) -> bool:
        """
        Block internet access for an application.

        Args:
            app_path: Path to the application executable.
            rule_name: Optional custom name for the rule.

        Returns:
            True if successful, False otherwise.
        """
        if not rule_name:
            app_name = os.path.basename(app_path)
            rule_name = f"NetGuardian Block - {app_name}"

        try:
            outbound_result = subprocess.run([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name} (Outbound)"
            ], capture_output=True, text=True)

            if "No rules match the specified criteria" not in outbound_result.stdout:
                self.enable_rule(f"{rule_name} (Outbound)")
            else:
                # Block outbound connections
                outbound_result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name} (Outbound)",
                    f"program={app_path}",
                    "dir=out",
                    "action=block",
                    "enable=yes",
                    "profile=any",
                    f"description=NetGuardian"
                ], capture_output=True, text=True, check=True)

            # Block inbound connections
            inbound_result = subprocess.run([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name} (Inbound)"
            ], capture_output=True, text=True)

            if "No rules match the specified criteria" not in inbound_result.stdout:
                self.enable_rule(f"{rule_name} (Inbound)")
            else:
                inbound_result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name} (Inbound)",
                    f"program={app_path}",
                    "dir=in",
                    "action=block",
                    "enable=yes",
                    "profile=any",
                    f"description=NetGuardian"
                ], capture_output=True, text=True, check=True)

            logger.info(f"Successfully blocked internet access for {app_path}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {app_path}: {e}")
            logger.error(f"Command output: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error blocking {app_path}: {e}")
            return False

    def allow_app(self, app_path: str, rule_name: Optional[str] = None) -> bool:
        """
        Allow internet access for an application.

        Args:
            app_path: Path to the application executable.
            rule_name: Optional custom name for the rule.

        Returns:
            True if successful, False otherwise.
        """
        if not rule_name:
            app_name = os.path.basename(app_path)
            rule_name = f"NetGuardian Block - {app_name}"

        try:
            outbound_result = subprocess.run([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name} (Outbound)"
            ], capture_output=True, text=True, check=True)

            if "No rules match the specified criteria" not in outbound_result.stdout:
                self.disable_rule(f"{rule_name} (Outbound)")
            else:
                # Create outbound allow rule
                outbound_result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name} (Outbound)",
                    f"program={app_path}",
                    "dir=out",
                    "action=block",
                    "enable=no",
                    "profile=any",
                    f"description=NetGuardian"
                ], capture_output=True, text=True, check=True)

            # Create inbound allow rule
            inbound_result = subprocess.run([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name} (Inbound)"
            ], capture_output=True, text=True, check=True)

            if "No rules match the specified criteria" not in inbound_result.stdout:
                self.disable_rule(f"{rule_name} (Inbound)")
            else:
                inbound_result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name} (Inbound)",
                    f"program={app_path}",
                    "dir=in",
                    "action=block",
                    "enable=no",
                    "profile=any",
                    f"description=NetGuardian"
                ], capture_output=True, text=True, check=True)

            logger.info(f"Successfully allowed internet access for {app_path}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to allow {app_path}: {e}")
            logger.error(f"Command output: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error allowing {app_path}: {e}")
            return False

    def remove_app_rules(self, app_path: str) -> bool:
        """
        Remove all firewall rules for an application.

        Args:
            app_path: Path to the application executable.

        Returns:
            True if successful, False otherwise.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot remove app rules: No administrator privileges")
            return False

        # Check if the app path exists - but we'll try to remove rules even if it doesn't
        # since there might be orphaned rules
        if not os.path.exists(app_path):
            logger.warning(f"App path does not exist, but will try to remove rules anyway: {app_path}")

        try:
            # Get existing rules first to check if there are any
            existing_rules = self.get_app_rules(app_path)
            if not existing_rules:
                logger.info(f"No firewall rules found for {app_path}")
                return True

            # Delete all rules for this program
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"program={app_path}"
            ], capture_output=True, text=True, check=True)

            # Verify rules were removed
            remaining_rules = self.get_app_rules(app_path)
            if remaining_rules:
                logger.warning(f"Some rules remain after deletion for {app_path}: {len(remaining_rules)} rules")

                # Try to delete each rule by name as a fallback
                for rule in remaining_rules:
                    if "name" in rule:
                        try:
                            subprocess.run([
                                "netsh", "advfirewall", "firewall", "delete", "rule",
                                f"name={rule['name']}"
                            ], capture_output=True, text=True, check=True)
                            logger.info(f"Deleted rule by name: {rule['name']}")
                        except Exception as e:
                            logger.error(f"Failed to delete rule by name {rule['name']}: {e}")

            logger.info(f"Successfully removed firewall rules for {app_path}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove rules for {app_path}: {e}")
            logger.error(f"Command output: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error removing rules for {app_path}: {e}")
            return False

    def is_app_blocked(self, app_path: str) -> bool:
        """
        Check if an application is blocked.

        Args:
            app_path: Path to the application executable.

        Returns:
            True if blocked, False if allowed or no rules exist.
        """
        # If the app doesn't exist, we can't determine its status
        if not os.path.exists(app_path):
            logger.warning(f"Cannot determine block status: File does not exist: {app_path}")
            return False

        rules = self.get_app_rules(app_path)

        # Count block and allow rules
        block_rules = 0
        allow_rules = 0

        for rule in rules:
            action = rule.get("action", "").lower()
            if action == "block":
                block_rules += 1
            elif action == "allow":
                allow_rules += 1

        # If there are any allow rules, consider it allowed, overriding any block rules
        if allow_rules > 0:
            logger.debug(f"App {app_path} is allowed (found {block_rules} block rules, {allow_rules} allow rules)")
            return False

        # If there are any block rules, consider it blocked
        if block_rules > 0:
            logger.debug(f"App {app_path} is blocked (found {block_rules} block rules, {allow_rules} allow rules)")
            return True

        logger.debug(f"App {app_path} is allowed (found {block_rules} block rules, {allow_rules} allow rules)")
        return False

    def create_custom_rule(self,
                          name: str,
                          program: Optional[str] = None,
                          direction: str = "out",
                          action: str = "block",
                          protocol: str = "any",
                          local_port: Optional[str] = None,
                          remote_port: Optional[str] = None,
                          local_ip: Optional[str] = None,
                          remote_ip: Optional[str] = None) -> bool:
        """
        Create a custom firewall rule.

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

        Returns:
            True if successful, False otherwise.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot create custom rule: No administrator privileges")
            return False

        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"dir={direction}",
            f"action={action}",
            "enable=yes",
            f"protocol={protocol}",
            "profile=any"
        ]

        if program:
            cmd.append(f"program={program}")

        if local_port:
            cmd.append(f"localport={local_port}")

        if remote_port:
            cmd.append(f"remoteport={remote_port}")

        if local_ip:
            cmd.append(f"localip={local_ip}")

        if remote_ip:
            cmd.append(f"remoteip={remote_ip}")

        try:
            subprocess.run(cmd, check=True)
            logger.info(f"Successfully created custom rule: {name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create custom rule {name}: {e}")
            return False

    def delete_rule(self, rule_name: str) -> bool:
        """
        Delete a firewall rule by name.

        Args:
            rule_name: Name of the rule to delete.

        Returns:
            True if successful, False otherwise.
        """
        # Check if we have admin privileges
        if not self.has_admin:
            logger.warning("Cannot delete rule: No administrator privileges")
            return False

        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], check=True)

            logger.info(f"Successfully deleted rule: {rule_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete rule {rule_name}: {e}")
            return False
