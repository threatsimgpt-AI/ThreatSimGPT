"""Template Audit Service with proper security and log rotation.

Provides comprehensive audit logging for template operations with:
- Log rotation to prevent disk space exhaustion
- Secure log entry formatting
- Structured logging for analysis
- Configurable retention policies
"""

import logging
import logging.handlers
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from threatsimgpt.security.template_validator import SecurityValidationResult


class TemplateAuditService:
    """Comprehensive audit logging service for template operations.
    
    Provides secure, structured logging with rotation and retention
    policies to prevent disk exhaustion and maintain audit trails.
    """
    
    def __init__(
        self,
        log_dir: Optional[Path] = None,
        log_file: str = "template_audit.log",
        max_bytes: int = 10_000_000,  # 10MB per log file
        backup_count: int = 5,  # Keep 5 backup files
        retention_days: int = 30,
        enable_console: bool = False
    ):
        """Initialize audit service with secure logging configuration.
        
        Args:
            log_dir: Directory for audit logs (defaults to ./logs)
            log_file: Base name for log file
            max_bytes: Maximum bytes per log file before rotation
            backup_count: Number of backup files to keep
            retention_days: Days to retain logs before cleanup
            enable_console: Enable console output for debugging
        """
        self.log_dir = log_dir or Path("logs")
        self.log_file = log_file
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.retention_days = retention_days
        self.enable_console = enable_console
        
        # Ensure log directory exists
        self.log_dir.mkdir(exist_ok=True, parents=True)
        
        # Setup logger with proper handlers
        self.logger = self._setup_logger()
        
        # Log service initialization
        self.log_service_event("AUDIT_SERVICE_INITIALIZED", {
            "log_dir": str(self.log_dir),
            "max_bytes": self.max_bytes,
            "backup_count": self.backup_count,
            "retention_days": self.retention_days
        })
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with secure handlers and formatting."""
        logger = logging.getLogger('threatsimgpt.template_audit')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers to prevent duplicates
        logger.handlers.clear()
        
        # Create formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        
        # File handler with rotation
        log_path = self.log_dir / self.log_file
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Optional console handler for debugging
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.DEBUG)
            logger.addHandler(console_handler)
        
        return logger
    
    def _sanitize_for_log(self, value: Any) -> str:
        """Sanitize value for safe logging.
        
        Prevents log injection by escaping control characters
        and limiting length to prevent log abuse.
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized string safe for logging
        """
        if value is None:
            return ""
        
        # Convert to string and limit length
        str_value = str(value)
        if len(str_value) > 1000:
            str_value = str_value[:1000] + "...[truncated]"
        
        # Escape control characters
        dangerous_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', 
                          '\x06', '\x07', '\x08', '\x0b', '\x0c', '\x0e', '\x0f']
        for char in dangerous_chars:
            str_value = str_value.replace(char, f'\\x{ord(char):02x}')
        
        # Remove newlines to prevent log injection
        str_value = str_value.replace('\n', '\\n').replace('\r', '\\r')
        
        return str_value
    
    def _format_log_entry(self, event_type: str, details: Dict[str, Any]) -> str:
        """Format structured log entry.
        
        Args:
            event_type: Type of event being logged
            details: Event details
            
        Returns:
            Formatted log entry string
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Sanitize all values
        safe_details = {
            key: self._sanitize_for_log(value)
            for key, value in details.items()
        }
        
        # Create structured entry
        entry_parts = [
            f"EVENT={event_type}",
            f"TIMESTAMP={timestamp}"
        ]
        
        # Add details in consistent order
        for key in sorted(safe_details.keys()):
            entry_parts.append(f"{key.upper()}={safe_details[key]}")
        
        return " | ".join(entry_parts)
    
    def log_validation_attempt(
        self, 
        template_file: str, 
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> None:
        """Log template validation attempt.
        
        Args:
            template_file: Path or name of template file
            user_id: Optional user identifier
            source_ip: Optional source IP address
        """
        details = {
            "template_file": template_file,
            "user_id": user_id or "anonymous",
            "source_ip": source_ip or "unknown"
        }
        
        entry = self._format_log_entry("VALIDATION_ATTEMPT", details)
        self.logger.info(entry)
    
    def log_validation_result(
        self,
        template_file: str,
        result: SecurityValidationResult,
        cache_hit: bool = False,
        user_id: Optional[str] = None,
        validation_duration_ms: Optional[float] = None
    ) -> None:
        """Log template validation result.
        
        Args:
            template_file: Path or name of template file
            result: Security validation result
            cache_hit: Whether result came from cache
            user_id: Optional user identifier
            validation_duration_ms: Validation duration in milliseconds
        """
        status = "SECURE" if result.is_secure else "BLOCKED"
        
        details = {
            "template_file": template_file,
            "status": status,
            "findings_count": len(result.findings),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "cache_hit": str(cache_hit),
            "validation_id": result.validation_id,
            "user_id": user_id or "anonymous"
        }
        
        if validation_duration_ms is not None:
            details["duration_ms"] = f"{validation_duration_ms:.2f}"
        
        entry = self._format_log_entry("VALIDATION_RESULT", details)
        
        # Use appropriate log level
        if not result.is_secure and result.critical_count > 0:
            self.logger.error(entry)  # Critical issues
        elif not result.is_secure:
            self.logger.warning(entry)  # Non-critical issues
        else:
            self.logger.info(entry)  # Successful validation
    
    def log_template_operation(
        self,
        operation: str,
        template_file: str,
        user_id: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log general template operations.
        
        Args:
            operation: Type of operation (CREATE, UPDATE, DELETE, FIX, etc.)
            template_file: Path or name of template file
            user_id: Optional user identifier
            success: Whether operation was successful
            details: Additional operation details
        """
        base_details = {
            "operation": operation,
            "template_file": template_file,
            "user_id": user_id or "anonymous",
            "success": str(success)
        }
        
        if details:
            # Sanitize and merge additional details
            safe_details = {
                key: self._sanitize_for_log(value)
                for key, value in details.items()
            }
            base_details.update(safe_details)
        
        entry = self._format_log_entry("TEMPLATE_OPERATION", base_details)
        
        if success:
            self.logger.info(entry)
        else:
            self.logger.warning(entry)
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security-related events.
        
        Args:
            event_type: Type of security event
            severity: Event severity (LOW, MEDIUM, HIGH, CRITICAL)
            description: Event description
            user_id: Optional user identifier
            details: Additional event details
        """
        base_details = {
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "user_id": user_id or "anonymous"
        }
        
        if details:
            safe_details = {
                key: self._sanitize_for_log(value)
                for key, value in details.items()
            }
            base_details.update(safe_details)
        
        entry = self._format_log_entry("SECURITY_EVENT", base_details)
        
        # Use appropriate log level based on severity
        log_level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH": logging.ERROR,
            "MEDIUM": logging.WARNING,
            "LOW": logging.INFO
        }.get(severity.upper(), logging.INFO)
        
        self.logger.log(log_level, entry)
    
    def log_service_event(
        self,
        event_type: str,
        details: Dict[str, Any]
    ) -> None:
        """Log service-level events.
        
        Args:
            event_type: Type of service event
            details: Event details
        """
        entry = self._format_log_entry("SERVICE_EVENT", details)
        self.logger.info(entry)
    
    def cleanup_old_logs(self) -> int:
        """Clean up log files older than retention period.
        
        Returns:
            Number of files cleaned up
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        cleaned_count = 0
        
        try:
            for log_file in self.log_dir.glob(f"{self.log_file}*"):
                if log_file.is_file():
                    file_time = datetime.fromtimestamp(
                        log_file.stat().st_mtime, 
                        timezone.utc
                    )
                    
                    if file_time < cutoff_date:
                        log_file.unlink()
                        cleaned_count += 1
                        
                        # Log cleanup
                        self.log_service_event("LOG_CLEANUP", {
                            "file": str(log_file),
                            "file_date": file_time.isoformat(),
                            "cutoff_date": cutoff_date.isoformat()
                        })
        
        except Exception as e:
            self.log_service_event("LOG_CLEANUP_ERROR", {
                "error": str(e),
                "cutoff_date": cutoff_date.isoformat()
            })
        
        return cleaned_count
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics and information.
        
        Returns:
            Dictionary with log statistics
        """
        stats = {
            "log_dir": str(self.log_dir),
            "log_file": self.log_file,
            "max_bytes": self.max_bytes,
            "backup_count": self.backup_count,
            "retention_days": self.retention_days,
            "enable_console": self.enable_console
        }
        
        # Calculate total log size
        try:
            total_size = sum(
                f.stat().st_size 
                for f in self.log_dir.glob(f"{self.log_file}*") 
                if f.is_file()
            )
            stats["total_size_bytes"] = total_size
            stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)
        except Exception:
            stats["total_size_bytes"] = 0
            stats["total_size_mb"] = 0.0
        
        # Count log files
        try:
            log_files = list(self.log_dir.glob(f"{self.log_file}*"))
            stats["file_count"] = len(log_files)
            
            if log_files:
                latest_file = max(log_files, key=lambda f: f.stat().st_mtime)
                stats["latest_file"] = str(latest_file)
                stats["latest_modified"] = datetime.fromtimestamp(
                    latest_file.stat().st_mtime,
                    timezone.utc
                ).isoformat()
        except Exception:
            stats["file_count"] = 0
        
        return stats
