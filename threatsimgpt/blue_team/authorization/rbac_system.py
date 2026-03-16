"""
Role-Based Access Control (RBAC) System

This module implements the core RBAC system for blue team operations,
providing hierarchical role management and permission enforcement.

Author: Ibrahim Hassan
Created: March 2026
"""

from __future__ import annotations
import asyncio
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from uuid import uuid4

from ..models import (
    BlueTeamRole,
    OperationType,
    PermissionLevel,
    Permission,
    AuthorizationRequest,
    AuthorizationResult,
    UserSession,
    RolePermissions,
    DEFAULT_ROLE_PERMISSIONS,
)
from ..exceptions import (
    BlueTeamAuthError,
    InsufficientPermissionsError,
    InvalidRoleError,
    SessionExpiredError,
    ConfigurationError,
)


logger = logging.getLogger(__name__)


class RBACSystem:
    """
    Role-Based Access Control system for blue team operations

    Provides hierarchical role management, permission checking,
    and session management for secure blue team operations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize RBAC system

        Args:
            config: Configuration dictionary for RBAC system
        """
        self.config = config or {}
        self._role_permissions: Dict[BlueTeamRole, RolePermissions] = {}
        self._user_sessions: Dict[str, UserSession] = {}
        self._user_roles: Dict[str, BlueTeamRole] = {}
        self._session_timeout = self.config.get("session_timeout", 3600)  # 1 hour default

        # Initialize default role permissions
        self._initialize_default_roles()

        logger.info("RBAC System initialized")

    def _initialize_default_roles(self) -> None:
        """Initialize default role permissions"""
        try:
            for role, config in DEFAULT_ROLE_PERMISSIONS.items():
                permissions = set()
                for operation, level in config["permissions"].items():
                    permissions.add(Permission(operation=operation, level=level))

                role_perms = RolePermissions(
                    role=role,
                    permissions=permissions,
                    time_restrictions=config.get("time_restrictions", {}),
                    approval_required=config.get("approval_required", set()),
                )

                self._role_permissions[role] = role_perms

            logger.info(f"Initialized {len(self._role_permissions)} default roles")

        except Exception as e:
            raise ConfigurationError("RBAC initialization", f"Failed to initialize default roles: {str(e)}")

    async def assign_role(self, user_id: str, role: BlueTeamRole) -> bool:
        """
        Assign a role to a user

        Args:
            user_id: User identifier
            role: Role to assign

        Returns:
            True if role assigned successfully

        Raises:
            InvalidRoleError: If role is invalid
        """
        try:
            if role not in BlueTeamRole:
                raise InvalidRoleError(role.value)

            self._user_roles[user_id] = role

            # Invalidate existing sessions for this user
            await self._invalidate_user_sessions(user_id)

            logger.info(f"Assigned role {role.value} to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to assign role {role.value} to user {user_id}: {str(e)}")
            raise

    async def create_session(self, user_id: str, context: Optional[Dict[str, Any]] = None) -> UserSession:
        """
        Create a new user session

        Args:
            user_id: User identifier
            context: Session context information

        Returns:
            Created user session

        Raises:
            BlueTeamAuthError: If user not found or session creation fails
        """
        try:
            if user_id not in self._user_roles:
                raise BlueTeamAuthError(f"User {user_id} not found in system", "USER_NOT_FOUND")

            role = self._user_roles[user_id]
            session_id = secrets.token_urlsafe(32)

            # Get role permissions
            role_perms = self._role_permissions.get(role)
            if not role_perms:
                raise ConfigurationError("RBAC", f"No permissions defined for role {role.value}")

            # Extract permission strings
            permissions = {f"{perm.level.value}:{perm.operation.value}" for perm in role_perms.permissions}

            # Create session
            session = UserSession(
                user_id=user_id,
                role=role,
                session_id=session_id,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(seconds=self._session_timeout),
                permissions=permissions,
            )

            self._user_sessions[session_id] = session

            logger.info(f"Created session {session_id} for user {user_id} with role {role.value}")
            return session

        except Exception as e:
            logger.error(f"Failed to create session for user {user_id}: {str(e)}")
            raise

    async def authorize(self, request: AuthorizationRequest) -> AuthorizationResult:
        """
        Authorize a blue team operation

        Args:
            request: Authorization request

        Returns:
            Authorization result

        Raises:
            BlueTeamAuthError: If authorization fails
        """
        try:
            # Get user role
            user_role = self._user_roles.get(request.user_id)
            if not user_role:
                raise BlueTeamAuthError(f"User {request.user_id} not found", "USER_NOT_FOUND")

            # Get role permissions
            role_perms = self._role_permissions.get(user_role)
            if not role_perms:
                raise ConfigurationError("RBAC", f"No permissions defined for role {user_role.value}")

            # Check basic permission
            has_permission = role_perms.has_permission(request.operation, PermissionLevel.READ)
            if not has_permission:
                raise InsufficientPermissionsError(
                    request.user_id, f"{request.operation.value}:{PermissionLevel.READ.value}", user_role.value
                )

            # Generate audit ID
            audit_id = str(uuid4())

            # Create authorization result
            result = AuthorizationResult(request=request, authorized=True, audit_id=audit_id)

            logger.info(f"Authorized {request.operation.value} for user {request.user_id}")
            return result

        except BlueTeamAuthError:
            # Re-raise known exceptions
            raise
        except Exception as e:
            logger.error(f"Authorization failed for user {request.user_id}: {str(e)}")
            raise BlueTeamAuthError(f"Authorization failed: {str(e)}", "AUTHORIZATION_ERROR")

    async def check_session_permission(
        self, session_id: str, operation: OperationType, level: PermissionLevel = PermissionLevel.READ
    ) -> bool:
        """
        Check if session has permission for specific operation

        Args:
            session_id: Session identifier
            operation: Operation type to check
            level: Permission level required

        Returns:
            True if session has permission

        Raises:
            SessionExpiredError: If session is expired
            BlueTeamAuthError: If session is invalid
        """
        try:
            session = self._user_sessions.get(session_id)
            if not session:
                raise BlueTeamAuthError(f"Session {session_id} not found", "SESSION_NOT_FOUND")

            if session.is_expired():
                raise SessionExpiredError(session.user_id, session_id, session.expires_at.isoformat())

            # Check permission
            required_permission = f"{level.value}:{operation.value}"
            return session.has_permission(required_permission)

        except (SessionExpiredError, BlueTeamAuthError):
            raise
        except Exception as e:
            logger.error(f"Permission check failed for session {session_id}: {str(e)}")
            raise BlueTeamAuthError(f"Permission check failed: {str(e)}", "PERMISSION_CHECK_ERROR")

    async def refresh_session(self, session_id: str) -> UserSession:
        """
        Refresh an existing session

        Args:
            session_id: Session identifier

        Returns:
            Refreshed session

        Raises:
            BlueTeamAuthError: If session is invalid
        """
        try:
            session = self._user_sessions.get(session_id)
            if not session:
                raise BlueTeamAuthError(f"Session {session_id} not found", "SESSION_NOT_FOUND")

            if session.is_expired():
                raise SessionExpiredError(session.user_id, session_id, session.expires_at.isoformat())

            # Extend session expiration
            session.expires_at = datetime.utcnow() + timedelta(seconds=self._session_timeout)

            logger.info(f"Refreshed session {session_id} for user {session.user_id}")
            return session

        except (SessionExpiredError, BlueTeamAuthError):
            raise
        except Exception as e:
            logger.error(f"Session refresh failed for {session_id}: {str(e)}")
            raise BlueTeamAuthError(f"Session refresh failed: {str(e)}", "SESSION_REFRESH_ERROR")

    async def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a user session

        Args:
            session_id: Session identifier

        Returns:
            True if session revoked successfully
        """
        try:
            session = self._user_sessions.get(session_id)
            if not session:
                return False

            session.active = False
            del self._user_sessions[session_id]

            logger.info(f"Revoked session {session_id} for user {session.user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke session {session_id}: {str(e)}")
            return False

    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """
        Get all permissions for a user

        Args:
            user_id: User identifier

        Returns:
            Set of permission strings

        Raises:
            BlueTeamAuthError: If user not found
        """
        try:
            role = self._user_roles.get(user_id)
            if not role:
                raise BlueTeamAuthError(f"User {user_id} not found", "USER_NOT_FOUND")

            role_perms = self._role_permissions.get(role)
            if not role_perms:
                return set()

            return {f"{perm.level.value}:{perm.operation.value}" for perm in role_perms.permissions}

        except BlueTeamAuthError:
            raise
        except Exception as e:
            logger.error(f"Failed to get permissions for user {user_id}: {str(e)}")
            raise BlueTeamAuthError(f"Failed to get permissions: {str(e)}", "PERMISSION_ERROR")

    async def add_custom_permission(self, role: BlueTeamRole, permission: Permission) -> bool:
        """
        Add custom permission to a role

        Args:
            role: Role to modify
            permission: Permission to add

        Returns:
            True if permission added successfully
        """
        try:
            role_perms = self._role_permissions.get(role)
            if not role_perms:
                role_perms = RolePermissions(role=role)
                self._role_permissions[role] = role_perms

            role_perms.permissions.add(permission)

            logger.info(f"Added permission {permission} to role {role.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to add permission to role {role.value}: {str(e)}")
            return False

    async def remove_permission(self, role: BlueTeamRole, operation: OperationType) -> bool:
        """
        Remove permission from a role

        Args:
            role: Role to modify
            operation: Operation to remove

        Returns:
            True if permission removed successfully
        """
        try:
            role_perms = self._role_permissions.get(role)
            if not role_perms:
                return False

            # Remove permission for this operation
            role_perms.permissions = {perm for perm in role_perms.permissions if perm.operation != operation}

            logger.info(f"Removed permission for {operation.value} from role {role.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove permission from role {role.value}: {str(e)}")
            return False

    async def _invalidate_user_sessions(self, user_id: str) -> None:
        """Invalidate all sessions for a user"""
        sessions_to_remove = []
        for session_id, session in self._user_sessions.items():
            if session.user_id == user_id:
                sessions_to_remove.append(session_id)

        for session_id in sessions_to_remove:
            await self.revoke_session(session_id)

    def get_role_hierarchy(self) -> Dict[str, int]:
        """
        Get role hierarchy levels

        Returns:
            Dictionary mapping role names to hierarchy levels
        """
        return {
            BlueTeamRole.VIEWER.value: 0,
            BlueTeamRole.ANALYST.value: 1,
            BlueTeamRole.SENIOR_ANALYST.value: 2,
            BlueTeamRole.TEAM_LEAD.value: 3,
            BlueTeamRole.MANAGER.value: 4,
            BlueTeamRole.ADMIN.value: 5,
        }

    async def get_system_stats(self) -> Dict[str, Any]:
        """
        Get RBAC system statistics

        Returns:
            System statistics dictionary
        """
        active_sessions = len([s for s in self._user_sessions.values() if s.active and not s.is_expired()])

        return {
            "total_users": len(self._user_roles),
            "active_sessions": active_sessions,
            "configured_roles": len(self._role_permissions),
            "session_timeout": self._session_timeout,
            "role_distribution": {
                role.value: len([u for u, r in self._user_roles.items() if r == role]) for role in BlueTeamRole
            },
        }
