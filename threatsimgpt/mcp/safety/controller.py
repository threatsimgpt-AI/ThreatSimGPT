"""
Safety Controller

Validates commands and operations to prevent dangerous actions.
This is a CRITICAL security component - all operations must pass through
safety validation before execution.

Features:
    - Command validation against blocklist
    - Network target validation (only attack network)
    - Scenario approval requirements
    - Audit logging of all operations

Usage:
    from threatsimgpt.mcp.safety import SafetyController
    from threatsimgpt.mcp.config import SafetyConfig

    safety = SafetyController(SafetyConfig())

    # Validate a command
    is_safe, reason = safety.validate_command("rm -rf /")
    # Returns: (False, "Command contains blocked pattern: rm -rf /")

    # Validate network target
    is_safe, reason = safety.validate_network("10.0.100.50")
    # Returns: (True, "IP is in allowed network")
"""

import re
import ipaddress
import logging
from typing import Tuple, List, Optional
from datetime import datetime

from ..config import SafetyConfig

logger = logging.getLogger(__name__)


class SafetyViolation(Exception):
    """Exception raised when safety validation fails."""

    def __init__(self, message: str, operation: str = None, details: dict = None):
        super().__init__(message)
        self.operation = operation
        self.details = details or {}
        self.timestamp = datetime.utcnow()


class SafetyController:
    """
    Validates operations for safety before execution.

    CRITICAL: This controller prevents:
    - Destructive commands (rm -rf /, dd, mkfs, etc.)
    - Operations outside allowed networks
    - Excessive resource usage
    - Dangerous scenarios without approval

    All MCP tool calls should validate through this controller.

    Attributes:
        config: SafetyConfig with safety rules
        audit_log: List of all validation attempts (for debugging)
    """

    def __init__(self, config: SafetyConfig):
        """
        Initialize safety controller.

        Args:
            config: SafetyConfig with blocklists and rules
        """
        self.config = config
        self.audit_log: List[dict] = []
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        self._blocked_patterns = []

        # Compile explicit blocked commands as escaped patterns
        for cmd in self.config.blocked_commands:
            try:
                # Escape special regex characters and create pattern
                pattern = re.compile(re.escape(cmd), re.IGNORECASE)
                self._blocked_patterns.append((pattern, f"blocked command: {cmd}"))
            except re.error as e:
                logger.warning(f"Invalid pattern '{cmd}': {e}")

        # Compile regex patterns
        for pattern_str in self.config.blocked_patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                self._blocked_patterns.append((pattern, f"blocked pattern: {pattern_str}"))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_str}': {e}")

    def validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Validate a shell command for safety.

        Checks against:
        - Blocked commands list
        - Blocked regex patterns
        - Dangerous shell constructs

        Args:
            command: Shell command to validate

        Returns:
            Tuple of (is_safe: bool, reason: str)

        Example:
            >>> safety.validate_command("whoami")
            (True, "Command is safe")
            >>> safety.validate_command("rm -rf /")
            (False, "Command contains blocked command: rm -rf /")
        """
        self._log_validation("command", command)

        # Check against compiled patterns
        for pattern, description in self._blocked_patterns:
            if pattern.search(command):
                reason = f"Command contains {description}"
                self._log_validation("command", command, blocked=True, reason=reason)
                return False, reason

        # Check for dangerous shell constructs
        dangerous_constructs = [
            (r'\$\(.*\)', "command substitution $()"),
            (r'`[^`]+`', "backtick command substitution"),
            (r'>\s*/dev/[sh]d[a-z]', "writing to disk device"),
            (r'>\s*/dev/null.*2>&1.*&\s*$', "hidden background process"),
            (r'\|\s*sh\s*$', "piping to shell"),
            (r'\|\s*bash\s*$', "piping to bash"),
            (r'eval\s+', "eval command"),
            (r'source\s+/dev/', "sourcing from device"),
        ]

        for pattern, description in dangerous_constructs:
            if re.search(pattern, command, re.IGNORECASE):
                reason = f"Command contains dangerous construct: {description}"
                self._log_validation("command", command, blocked=True, reason=reason)
                return False, reason

        self._log_validation("command", command, blocked=False)
        return True, "Command is safe"

    def validate_network(self, ip: str) -> Tuple[bool, str]:
        """
        Validate IP address is within allowed networks.

        CRITICAL: Only attack network IPs should be allowed.
        This prevents attacks escaping to production networks.

        Args:
            ip: IP address or hostname to validate

        Returns:
            Tuple of (is_allowed: bool, reason: str)

        Example:
            >>> safety.validate_network("10.0.100.50")
            (True, "IP is in allowed network: 10.0.100.0/24")
            >>> safety.validate_network("192.168.1.1")
            (False, "IP 192.168.1.1 is outside allowed networks")
        """
        self._log_validation("network", ip)

        # Try to parse as IP address
        try:
            target_ip = ipaddress.ip_address(ip)
        except ValueError:
            # Might be hostname - block by default
            reason = f"Cannot validate hostname '{ip}' - only IPs allowed"
            self._log_validation("network", ip, blocked=True, reason=reason)
            return False, reason

        # Check against allowed networks
        for network_str in self.config.allowed_networks:
            try:
                network = ipaddress.ip_network(network_str)
                if target_ip in network:
                    reason = f"IP is in allowed network: {network_str}"
                    self._log_validation("network", ip, blocked=False)
                    return True, reason
            except ValueError:
                continue

        reason = f"IP {ip} is outside allowed networks: {self.config.allowed_networks}"
        self._log_validation("network", ip, blocked=True, reason=reason)
        return False, reason

    def validate_scenario(self, scenario_name: str) -> Tuple[bool, str]:
        """
        Check if scenario requires manual approval.

        Some scenarios (ransomware, wiper, etc.) are too dangerous
        for automatic execution and require human approval.

        Args:
            scenario_name: Name of the attack scenario

        Returns:
            Tuple of (auto_approved: bool, reason: str)
        """
        self._log_validation("scenario", scenario_name)

        scenario_lower = scenario_name.lower()

        for restricted in self.config.require_approval:
            if restricted.lower() in scenario_lower:
                reason = f"Scenario '{scenario_name}' requires manual approval (contains '{restricted}')"
                self._log_validation("scenario", scenario_name, blocked=True, reason=reason)
                return False, reason

        self._log_validation("scenario", scenario_name, blocked=False)
        return True, "Scenario auto-approved"

    def validate_file_path(self, path: str) -> Tuple[bool, str]:
        """
        Validate file path is safe.

        Blocks access to sensitive system paths.

        Args:
            path: File path to validate

        Returns:
            Tuple of (is_safe: bool, reason: str)
        """
        self._log_validation("file_path", path)

        # Dangerous paths
        blocked_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/.ssh",
            "/home/*/.ssh",
            "/boot",
            "/dev/sd",
            "/dev/null",  # Writing to /dev/null might hide output
        ]

        path_lower = path.lower()

        for blocked in blocked_paths:
            if blocked.replace("*", "") in path_lower:
                reason = f"Path '{path}' matches blocked path pattern"
                self._log_validation("file_path", path, blocked=True, reason=reason)
                return False, reason

        # Check for path traversal
        if ".." in path:
            reason = "Path contains directory traversal (..)"
            self._log_validation("file_path", path, blocked=True, reason=reason)
            return False, reason

        self._log_validation("file_path", path, blocked=False)
        return True, "Path is safe"

    def validate_all(
        self,
        command: str = None,
        target_ip: str = None,
        scenario: str = None,
        file_path: str = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate multiple aspects of an operation.

        Convenience method to validate command, network, scenario,
        and file path in one call.

        Args:
            command: Optional command to validate
            target_ip: Optional target IP to validate
            scenario: Optional scenario name to validate
            file_path: Optional file path to validate

        Returns:
            Tuple of (all_safe: bool, list of reasons)
        """
        reasons = []
        all_safe = True

        if command:
            is_safe, reason = self.validate_command(command)
            if not is_safe:
                all_safe = False
                reasons.append(reason)

        if target_ip:
            is_safe, reason = self.validate_network(target_ip)
            if not is_safe:
                all_safe = False
                reasons.append(reason)

        if scenario:
            is_safe, reason = self.validate_scenario(scenario)
            if not is_safe:
                all_safe = False
                reasons.append(reason)

        if file_path:
            is_safe, reason = self.validate_file_path(file_path)
            if not is_safe:
                all_safe = False
                reasons.append(reason)

        return all_safe, reasons

    def assert_safe(
        self,
        command: str = None,
        target_ip: str = None,
        scenario: str = None,
        file_path: str = None
    ) -> None:
        """
        Assert all validations pass, raising exception if not.

        Use this in tool implementations to enforce safety.

        Args:
            command: Optional command to validate
            target_ip: Optional target IP to validate
            scenario: Optional scenario name to validate
            file_path: Optional file path to validate

        Raises:
            SafetyViolation: If any validation fails
        """
        all_safe, reasons = self.validate_all(
            command=command,
            target_ip=target_ip,
            scenario=scenario,
            file_path=file_path
        )

        if not all_safe:
            raise SafetyViolation(
                f"Safety validation failed: {'; '.join(reasons)}",
                details={
                    "command": command,
                    "target_ip": target_ip,
                    "scenario": scenario,
                    "file_path": file_path,
                    "reasons": reasons
                }
            )

    def _log_validation(
        self,
        validation_type: str,
        value: str,
        blocked: bool = None,
        reason: str = None
    ) -> None:
        """Log validation attempt for audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": validation_type,
            "value": value[:200],  # Truncate long values
            "blocked": blocked,
            "reason": reason
        }

        self.audit_log.append(entry)

        # Keep audit log bounded
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

        # Log to standard logger
        if blocked:
            logger.warning(f"SAFETY BLOCKED: {validation_type}={value[:100]} reason={reason}")
        elif blocked is False:
            logger.debug(f"Safety OK: {validation_type}={value[:100]}")

    def get_audit_log(self, limit: int = 100) -> List[dict]:
        """
        Get recent audit log entries.

        Args:
            limit: Maximum entries to return

        Returns:
            List of audit log entries (most recent first)
        """
        return list(reversed(self.audit_log[-limit:]))

    def get_blocked_count(self) -> int:
        """Get count of blocked operations."""
        return sum(1 for entry in self.audit_log if entry.get("blocked"))
