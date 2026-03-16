"""
Audit Logger

This module implements comprehensive audit logging for blue team operations,
providing complete audit trails for security and compliance requirements.

Author: Ibrahim Hassan
Created: March 2026
"""

from __future__ import annotations
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import uuid4

from ..models import AuditEvent, AuthorizationRequest, AuthorizationResult
from ..exceptions import AuditError, ConfigurationError


logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Comprehensive audit logging system for blue team operations
    
    Provides complete audit trails for all blue team activities,
    supporting compliance and security monitoring requirements.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize audit logger
        
        Args:
            config: Configuration dictionary for audit logging
        """
        self.config = config or {}
        self._audit_log_file = self.config.get('audit_log_file', 'logs/blue_team_audit.log')
        self._max_file_size = self.config.get('max_file_size', 100 * 1024 * 1024)  # 100MB
        self._backup_count = self.config.get('backup_count', 5)
        self._log_level = self.config.get('log_level', 'INFO')
        
        # Ensure log directory exists
        Path(self._audit_log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Setup audit logger
        self._setup_audit_logger()
        
        logger.info("Audit logger initialized")
    
    def _setup_audit_logger(self) -> None:
        """Setup dedicated audit logger with file rotation"""
        try:
            from logging.handlers import RotatingFileHandler
            
            # Create audit logger
            self._audit_logger = logging.getLogger('blue_team_audit')
            self._audit_logger.setLevel(getattr(logging, self._log_level))
            
            # Remove existing handlers
            self._audit_logger.handlers.clear()
            
            # File handler with rotation
            file_handler = RotatingFileHandler(
                self._audit_log_file,
                maxBytes=self._max_file_size,
                backupCount=self._backup_count
            )
            
            # Formatter for audit logs
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S UTC'
            )
            file_handler.setFormatter(formatter)
            
            self._audit_logger.addHandler(file_handler)
            
            # Prevent propagation to root logger
            self._audit_logger.propagate = False
            
        except Exception as e:
            raise ConfigurationError("AuditLogger", f"Failed to setup audit logger: {str(e)}")
    
    async def log_authorization_request(self, request: AuthorizationRequest) -> str:
        """
        Log authorization request
        
        Args:
            request: Authorization request to log
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=request.user_id,
                action=f"AUTH_REQUEST:{request.operation.value}",
                resource=request.resource,
                result="PENDING",
                details={
                    "role": request.role.value,
                    "operation": request.operation.value,
                    "context": request.context,
                    "timestamp": request.timestamp.isoformat()
                }
            )
            
            await self._write_audit_event(audit_event)
            
            logger.debug(f"Logged authorization request {event_id} for user {request.user_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log authorization request: {str(e)}"
            logger.error(error_msg)
            raise AuditError("authorization_request", error_msg)
    
    async def log_authorization_result(self, request: AuthorizationRequest, 
                                    result: AuthorizationResult) -> str:
        """
        Log authorization result
        
        Args:
            request: Original authorization request
            result: Authorization result
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=request.user_id,
                action=f"AUTH_RESULT:{request.operation.value}",
                resource=request.resource,
                result="AUTHORIZED" if result.authorized else "DENIED",
                details={
                    "role": request.role.value,
                    "operation": request.operation.value,
                    "authorized": result.authorized,
                    "reason": result.reason,
                    "approval_required": result.approval_required,
                    "approval_workflow_id": result.approval_workflow_id,
                    "time_restricted": result.time_restricted,
                    "session_duration": result.session_duration,
                    "audit_id": result.audit_id
                }
            )
            
            await self._write_audit_event(audit_event)
            
            logger.debug(f"Logged authorization result {event_id} for user {request.user_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log authorization result: {str(e)}"
            logger.error(error_msg)
            raise AuditError("authorization_result", error_msg)
    
    async def log_session_event(self, user_id: str, session_id: str, 
                              action: str, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log session-related event
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            action: Session action (created, expired, revoked, etc.)
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=user_id,
                action=f"SESSION:{action}",
                resource=session_id,
                result="SUCCESS",
                details=details or {}
            )
            
            await self._write_audit_event(audit_event)
            
            logger.debug(f"Logged session event {event_id}: {action} for user {user_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log session event: {str(e)}"
            logger.error(error_msg)
            raise AuditError("session_event", error_msg)
    
    async def log_approval_event(self, workflow_id: str, approver_id: str,
                               action: str, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log approval workflow event
        
        Args:
            workflow_id: Workflow identifier
            approver_id: Approver identifier
            action: Approval action (approved, rejected, created, etc.)
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=approver_id,
                action=f"APPROVAL:{action}",
                resource=workflow_id,
                result="SUCCESS",
                details=details or {}
            )
            
            await self._write_audit_event(audit_event)
            
            logger.debug(f"Logged approval event {event_id}: {action} by {approver_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log approval event: {str(e)}"
            logger.error(error_msg)
            raise AuditError("approval_event", error_msg)
    
    async def log_security_event(self, user_id: str, action: str,
                               resource: Optional[str] = None,
                               result: str = "SUCCESS",
                               details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log general security event
        
        Args:
            user_id: User identifier
            action: Security action
            resource: Resource identifier
            result: Event result
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=user_id,
                action=f"SECURITY:{action}",
                resource=resource,
                result=result,
                details=details or {}
            )
            
            await self._write_audit_event(audit_event)
            
            logger.debug(f"Logged security event {event_id}: {action} by {user_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log security event: {str(e)}"
            logger.error(error_msg)
            raise AuditError("security_event", error_msg)
    
    async def log_configuration_change(self, user_id: str, component: str,
                                     change_type: str, old_value: Any,
                                     new_value: Any) -> str:
        """
        Log configuration change event
        
        Args:
            user_id: User making the change
            component: Component being changed
            change_type: Type of change
            old_value: Previous value
            new_value: New value
            
        Returns:
            Audit event ID
        """
        try:
            event_id = str(uuid4())
            
            audit_event = AuditEvent(
                event_id=event_id,
                user_id=user_id,
                action=f"CONFIG:{change_type}",
                resource=component,
                result="SUCCESS",
                details={
                    "component": component,
                    "change_type": change_type,
                    "old_value": str(old_value) if old_value is not None else None,
                    "new_value": str(new_value) if new_value is not None else None
                }
            )
            
            await self._write_audit_event(audit_event)
            
            logger.info(f"Logged configuration change {event_id}: {component}.{change_type} by {user_id}")
            return event_id
            
        except Exception as e:
            error_msg = f"Failed to log configuration change: {str(e)}"
            logger.error(error_msg)
            raise AuditError("configuration_change", error_msg)
    
    async def _write_audit_event(self, event: AuditEvent) -> None:
        """Write audit event to log file"""
        try:
            # Convert to JSON for structured logging
            event_data = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "user_id": event.user_id,
                "action": event.action,
                "resource": event.resource,
                "result": event.result,
                "details": event.details,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent
            }
            
            # Write to audit log
            self._audit_logger.info(json.dumps(event_data, default=str))
            
        except Exception as e:
            logger.error(f"Failed to write audit event: {str(e)}")
            raise AuditError("write_event", f"Failed to write audit event: {str(e)}")
    
    async def search_audit_events(self, criteria: Dict[str, Any]) -> List[AuditEvent]:
        """
        Search audit events based on criteria
        
        Args:
            criteria: Search criteria (user_id, action, date_range, etc.)
            
        Returns:
            List of matching audit events
        """
        try:
            events = []
            
            # Read audit log file
            log_file = Path(self._audit_log_file)
            if not log_file.exists():
                return events
            
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        # Parse JSON from log line
                        if '|' in line:
                            json_part = line.split('|', 3)[-1].strip()
                            event_data = json.loads(json_part)
                            
                            # Apply search criteria
                            if self._matches_criteria(event_data, criteria):
                                # Convert back to AuditEvent
                                event = AuditEvent(
                                    event_id=event_data["event_id"],
                                    timestamp=datetime.fromisoformat(event_data["timestamp"]),
                                    user_id=event_data["user_id"],
                                    action=event_data["action"],
                                    resource=event_data.get("resource"),
                                    result=event_data["result"],
                                    details=event_data.get("details", {}),
                                    ip_address=event_data.get("ip_address"),
                                    user_agent=event_data.get("user_agent")
                                )
                                events.append(event)
                    
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        # Skip malformed lines
                        continue
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to search audit events: {str(e)}")
            return []
    
    def _matches_criteria(self, event_data: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        """Check if event data matches search criteria"""
        try:
            # User ID filter
            if "user_id" in criteria:
                if event_data.get("user_id") != criteria["user_id"]:
                    return False
            
            # Action filter
            if "action" in criteria:
                action_pattern = criteria["action"]
                if isinstance(action_pattern, str):
                    if action_pattern not in event_data.get("action", ""):
                        return False
                elif isinstance(action_pattern, list):
                    if not any(pattern in event_data.get("action", "") for pattern in action_pattern):
                        return False
            
            # Result filter
            if "result" in criteria:
                if event_data.get("result") != criteria["result"]:
                    return False
            
            # Date range filter
            if "date_from" in criteria or "date_to" in criteria:
                event_time = datetime.fromisoformat(event_data["timestamp"])
                
                if "date_from" in criteria:
                    if event_time < criteria["date_from"]:
                        return False
                
                if "date_to" in criteria:
                    if event_time > criteria["date_to"]:
                        return False
            
            # Resource filter
            if "resource" in criteria:
                if event_data.get("resource") != criteria["resource"]:
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Error matching criteria: {str(e)}")
            return False
    
    async def get_audit_summary(self, date_from: Optional[datetime] = None,
                              date_to: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Get audit summary statistics
        
        Args:
            date_from: Start date for summary
            date_to: End date for summary
            
        Returns:
            Audit summary dictionary
        """
        try:
            criteria = {}
            if date_from:
                criteria["date_from"] = date_from
            if date_to:
                criteria["date_to"] = date_to
            
            events = await self.search_audit_events(criteria)
            
            # Calculate statistics
            total_events = len(events)
            users = set(event.user_id for event in events)
            actions = {}
            results = {}
            
            for event in events:
                # Count actions
                action_type = event.action.split(':')[0]
                actions[action_type] = actions.get(action_type, 0) + 1
                
                # Count results
                results[event.result] = results.get(event.result, 0) + 1
            
            return {
                "total_events": total_events,
                "unique_users": len(users),
                "date_range": {
                    "from": date_from.isoformat() if date_from else None,
                    "to": date_to.isoformat() if date_to else None
                },
                "actions": actions,
                "results": results,
                "log_file": self._audit_log_file,
                "max_file_size": self._max_file_size,
                "backup_count": self._backup_count
            }
            
        except Exception as e:
            logger.error(f"Failed to get audit summary: {str(e)}")
            return {}
    
    async def export_audit_logs(self, output_file: str, 
                              date_from: Optional[datetime] = None,
                              date_to: Optional[datetime] = None) -> bool:
        """
        Export audit logs to file
        
        Args:
            output_file: Output file path
            date_from: Start date for export
            date_to: End date for export
            
        Returns:
            True if export successful
        """
        try:
            criteria = {}
            if date_from:
                criteria["date_from"] = date_from
            if date_to:
                criteria["date_to"] = date_to
            
            events = await self.search_audit_events(criteria)
            
            # Write events to output file
            with open(output_file, 'w') as f:
                for event in events:
                    event_data = {
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat(),
                        "user_id": event.user_id,
                        "action": event.action,
                        "resource": event.resource,
                        "result": event.result,
                        "details": event.details,
                        "ip_address": event.ip_address,
                        "user_agent": event.user_agent
                    }
                    f.write(json.dumps(event_data, default=str) + '\n')
            
            logger.info(f"Exported {len(events)} audit events to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export audit logs: {str(e)}")
            return False
