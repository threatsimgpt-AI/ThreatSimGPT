"""Safety controls for VM-based attack simulation.

This module provides safety mechanisms to prevent dangerous operations
during attack simulations, even in isolated lab environments.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class VMSafetyController:
    """
    Safety controller for VM attack simulations.

    Validates commands and actions to prevent:
    - Destructive operations (rm -rf /, format drives)
    - Network breakout attempts
    - Resource exhaustion attacks
    - Unauthorized access attempts

    Example:
        safety = VMSafetyController()

        is_safe, reason = safety.validate_command("nmap -sV target")
        if is_safe:
            # Execute command
        else:
            print(f"Blocked: {reason}")
    """

    # Commands that are always blocked
    BLOCKED_COMMANDS: Set[str] = {
        # Destructive
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "mkfs",
        "format c:",
        "del /f /s /q c:",
        "dd if=/dev/zero",
        "dd if=/dev/random",

        # Fork bombs
        ":(){ :|:& };:",
        "%0|%0",

        # Network breakout
        "iptables -F",
        "iptables -P INPUT ACCEPT",
        "route add default",

        # Crypto mining
        "xmrig",
        "minerd",
        "cgminer",
    }

    # Patterns that are blocked
    BLOCKED_PATTERNS: List[str] = [
        r"rm\s+-rf\s+/\s*$",
        r"rm\s+-rf\s+/\*",
        r">\s*/dev/sd[a-z]",
        r"dd\s+.*of=/dev/sd",
        r"mkfs\s+/dev/",
        r"curl.*\|\s*bash",
        r"wget.*\|\s*bash",
        r"curl.*\|\s*sh",
        r"wget.*\|\s*sh",
    ]

    # External IPs/domains that should be blocked (attack should stay in lab)
    BLOCKED_DESTINATIONS: Set[str] = {
        "8.8.8.8",
        "1.1.1.1",
        "google.com",
        "github.com",
        "pastebin.com",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize safety controller.

        Args:
            config: Optional configuration overrides
        """
        self.config = config or {}

        # Allow configuration to add/remove blocked items
        self.blocked_commands = self.BLOCKED_COMMANDS.copy()
        self.blocked_patterns = self.BLOCKED_PATTERNS.copy()
        self.blocked_destinations = self.BLOCKED_DESTINATIONS.copy()

        # Allowed network ranges (lab networks)
        self.allowed_networks = self.config.get("allowed_networks", [
            "10.0.100.",  # Default attack network
            "10.0.200.",  # Management network
            "192.168.",   # Local lab
            "172.16.",    # Docker default
            "localhost",
            "127.0.0.1",
        ])

        # Rate limiting
        self.max_commands_per_minute = self.config.get("max_commands_per_minute", 60)
        self._command_timestamps: List[float] = []

        # Audit log
        self.audit_log: List[Dict[str, Any]] = []

    def validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Validate if a command is safe to execute.

        Args:
            command: Command string to validate

        Returns:
            Tuple of (is_safe, reason)
        """
        command_lower = command.lower().strip()

        # Check blocked commands
        for blocked in self.blocked_commands:
            if blocked.lower() in command_lower:
                self._audit("BLOCKED", command, f"Contains blocked command: {blocked}")
                return False, f"Blocked command detected: {blocked}"

        # Check blocked patterns
        for pattern in self.blocked_patterns:
            if re.search(pattern, command_lower):
                self._audit("BLOCKED", command, f"Matches blocked pattern: {pattern}")
                return False, f"Blocked pattern detected: {pattern}"

        # Check for external network access
        for dest in self.blocked_destinations:
            if dest.lower() in command_lower:
                self._audit("BLOCKED", command, f"External destination: {dest}")
                return False, f"External network access blocked: {dest}"

        # Check if command targets allowed networks only
        ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ips = re.findall(ip_pattern, command)
        for ip in ips:
            if not self._is_allowed_ip(ip):
                self._audit("BLOCKED", command, f"Unauthorized IP: {ip}")
                return False, f"IP {ip} is outside allowed lab networks"

        # Rate limiting check
        if not self._check_rate_limit():
            self._audit("RATE_LIMITED", command, "Too many commands")
            return False, "Rate limit exceeded, slow down"

        self._audit("ALLOWED", command, "Passed all checks")
        return True, "OK"

    def validate_file_path(self, path: str, operation: str) -> Tuple[bool, str]:
        """
        Validate if a file operation is safe.

        Args:
            path: File path
            operation: Operation type (read, write, delete)

        Returns:
            Tuple of (is_safe, reason)
        """
        path_lower = path.lower()

        # Block system-critical paths
        blocked_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/boot",
            "/dev",
            "c:\\windows\\system32",
            "c:\\windows\\syswow64",
        ]

        for blocked in blocked_paths:
            if blocked in path_lower:
                if operation in ["write", "delete"]:
                    return False, f"Cannot {operation} system path: {blocked}"

        return True, "OK"

    def validate_network_target(self, target: str, port: Optional[int] = None) -> Tuple[bool, str]:
        """
        Validate if a network target is within allowed scope.

        Args:
            target: IP address or hostname
            port: Optional port number

        Returns:
            Tuple of (is_safe, reason)
        """
        # Check if in allowed networks
        if not self._is_allowed_ip(target) and target not in ["localhost"]:
            return False, f"Target {target} is outside lab network"

        # Check blocked ports (if we want to prevent certain services)
        blocked_ports = self.config.get("blocked_ports", [])
        if port in blocked_ports:
            return False, f"Port {port} is blocked"

        return True, "OK"

    def require_approval(self, action: str, details: Dict[str, Any]) -> bool:
        """
        Check if an action requires manual approval.

        Args:
            action: Action type
            details: Action details

        Returns:
            True if approval required
        """
        # Actions that always require approval
        approval_required = [
            "credential_dumping",
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration",
            "persistence",
        ]

        return action.lower() in approval_required

    def emergency_stop(self) -> None:
        """
        Emergency stop - block all further commands.

        Call this if attack simulation goes wrong.
        """
        logger.critical("EMERGENCY STOP ACTIVATED")

        # Block all commands
        self.max_commands_per_minute = 0

        # Log emergency
        self._audit("EMERGENCY_STOP", "ALL", "Emergency stop activated")

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the audit log of all command validations."""
        return self.audit_log.copy()

    def clear_audit_log(self) -> None:
        """Clear the audit log."""
        self.audit_log = []

    def _is_allowed_ip(self, ip: str) -> bool:
        """Check if IP is in allowed lab networks."""
        for network in self.allowed_networks:
            if ip.startswith(network):
                return True
        return False

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        import time

        current_time = time.time()
        minute_ago = current_time - 60

        # Remove old timestamps
        self._command_timestamps = [
            ts for ts in self._command_timestamps
            if ts > minute_ago
        ]

        # Check limit
        if len(self._command_timestamps) >= self.max_commands_per_minute:
            return False

        # Add current timestamp
        self._command_timestamps.append(current_time)
        return True

    def _audit(self, action: str, command: str, reason: str) -> None:
        """Add entry to audit log."""
        from datetime import datetime

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "command": command[:200],  # Truncate long commands
            "reason": reason,
        }

        self.audit_log.append(entry)

        if action == "BLOCKED":
            logger.warning(f"Command blocked: {command[:100]} - {reason}")
        elif action == "EMERGENCY_STOP":
            logger.critical(f"Emergency stop: {reason}")


class AttackScopeValidator:
    """
    Validates that attacks stay within defined scope.

    Use this to ensure attacks only target designated systems.
    """

    def __init__(self, scope: Dict[str, Any]):
        """Initialize with attack scope definition.

        Args:
            scope: Scope definition with allowed targets, techniques, etc.
        """
        self.allowed_targets: List[str] = scope.get("targets", [])
        self.allowed_techniques: List[str] = scope.get("techniques", [])
        self.excluded_systems: List[str] = scope.get("excluded", [])
        self.time_window: Optional[Dict[str, str]] = scope.get("time_window")

    def is_target_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        # Check exclusions first
        for excluded in self.excluded_systems:
            if excluded in target:
                return False

        # If specific targets defined, must match
        if self.allowed_targets:
            return any(allowed in target for allowed in self.allowed_targets)

        return True

    def is_technique_allowed(self, technique_id: str) -> bool:
        """Check if MITRE technique is allowed."""
        if not self.allowed_techniques:
            return True  # All techniques allowed if not specified

        return technique_id in self.allowed_techniques

    def is_within_time_window(self) -> bool:
        """Check if current time is within allowed window."""
        if not self.time_window:
            return True

        from datetime import datetime

        now = datetime.utcnow()

        start = self.time_window.get("start")
        end = self.time_window.get("end")

        if start:
            start_time = datetime.fromisoformat(start)
            if now < start_time:
                return False

        if end:
            end_time = datetime.fromisoformat(end)
            if now > end_time:
                return False

        return True
