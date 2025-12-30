"""
MCP Provider modules for different hypervisors.

Providers:
    - ProxmoxClient: Async client for Proxmox VE
    - (Future) DockerClient: For containerized testing
    - (Future) VMwareClient: For VMware environments
"""

from .proxmox import ProxmoxClient, ProxmoxError

__all__ = ["ProxmoxClient", "ProxmoxError"]
