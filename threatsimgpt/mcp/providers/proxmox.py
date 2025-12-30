"""
Proxmox VE API Client

Async client for Proxmox Virtual Environment REST API.
This is the primary hypervisor interface for ThreatSimGPT VM operations.

Features:
    - Async operations for parallel VM management
    - VM lifecycle (create, clone, start, stop, destroy)
    - Snapshot management
    - Console access (VNC tickets, keyboard input)
    - Guest agent integration for IP discovery

Usage:
    from threatsimgpt.mcp.providers import ProxmoxClient
    from threatsimgpt.mcp.config import ProxmoxConfig

    config = ProxmoxConfig(host="192.168.1.100", token_value="xxx")

    async with ProxmoxClient(config) as client:
        vms = await client.list_vms()
        vm_id = await client.clone_vm(9000, 200, "attack-target")
        await client.start_vm(vm_id)
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List

try:
    import aiohttp
except ImportError:
    aiohttp = None

from ..config import ProxmoxConfig

logger = logging.getLogger(__name__)


class ProxmoxError(Exception):
    """Exception raised for Proxmox API errors."""

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class ProxmoxClient:
    """
    Async Proxmox VE API client.

    Provides async methods for all VM operations needed by ThreatSimGPT.
    Uses API tokens for authentication (more secure than user/password).

    Attributes:
        config: ProxmoxConfig with connection settings
        base_url: Constructed API base URL
        headers: Authentication headers

    Example:
        async with ProxmoxClient(config) as client:
            # List all VMs
            vms = await client.list_vms()

            # Clone a template
            new_id = await client.clone_vm(9000, 200, "target-vm")

            # Start the VM
            await client.start_vm(200)

            # Wait for IP
            ip = await client.wait_for_ip(200, timeout=120)

            # Execute command via guest agent
            result = await client.execute_guest_command(200, "whoami")
    """

    def __init__(self, config: ProxmoxConfig):
        """
        Initialize Proxmox client.

        Args:
            config: ProxmoxConfig with connection settings
        """
        if aiohttp is None:
            raise ImportError("aiohttp is required: pip install aiohttp")

        self.config = config
        self.base_url = f"https://{config.host}:{config.port}/api2/json"
        self.headers = {
            "Authorization": f"PVEAPIToken={config.user}!{config.token_name}={config.token_value}"
        }
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "ProxmoxClient":
        """Async context manager entry - creates session."""
        connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
        self._session = aiohttp.ClientSession(
            headers=self.headers,
            connector=connector
        )
        logger.info(f"Connected to Proxmox at {self.config.host}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - closes session."""
        if self._session:
            await self._session.close()
            self._session = None
            logger.info("Disconnected from Proxmox")

    async def _ensure_session(self):
        """Ensure session is initialized."""
        if self._session is None:
            await self.__aenter__()

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        timeout: int = 30
    ) -> Any:
        """
        Make API request to Proxmox.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request body data
            timeout: Request timeout in seconds

        Returns:
            Response data (usually dict)

        Raises:
            ProxmoxError: If API returns error
        """
        await self._ensure_session()

        url = f"{self.base_url}{endpoint}"

        logger.debug(f"Proxmox API: {method} {endpoint}")

        try:
            async with self._session.request(
                method,
                url,
                data=data,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                result = await response.json()

                if response.status >= 400:
                    error_msg = result.get("errors", result.get("message", str(result)))
                    raise ProxmoxError(
                        f"API error: {error_msg}",
                        status_code=response.status,
                        response=result
                    )

                return result.get("data", result)

        except aiohttp.ClientError as e:
            raise ProxmoxError(f"Connection error: {str(e)}")

    # =========================================================================
    # VM Listing & Status
    # =========================================================================

    async def list_vms(self) -> List[Dict[str, Any]]:
        """
        List all VMs on the configured node.

        Returns:
            List of VM info dicts with keys: vmid, name, status, mem, cpu, etc.
        """
        return await self._request("GET", f"/nodes/{self.config.node}/qemu")

    async def get_vm(self, vmid: int) -> Dict[str, Any]:
        """
        Get detailed VM status.

        Args:
            vmid: VM ID

        Returns:
            Dict with VM status including state, memory, CPU usage
        """
        return await self._request(
            "GET",
            f"/nodes/{self.config.node}/qemu/{vmid}/status/current"
        )

    async def get_vm_config(self, vmid: int) -> Dict[str, Any]:
        """
        Get VM configuration.

        Args:
            vmid: VM ID

        Returns:
            Dict with VM configuration (cores, memory, disks, network, etc.)
        """
        return await self._request(
            "GET",
            f"/nodes/{self.config.node}/qemu/{vmid}/config"
        )

    # =========================================================================
    # VM Lifecycle
    # =========================================================================

    async def clone_vm(
        self,
        source_vmid: int,
        new_vmid: int,
        name: str,
        full: bool = True,
        description: str = ""
    ) -> int:
        """
        Clone a VM from template.

        Args:
            source_vmid: Source template VM ID
            new_vmid: New VM ID
            name: Name for new VM
            full: Full clone (True) or linked clone (False)
            description: Optional description

        Returns:
            New VM ID
        """
        logger.info(f"Cloning VM {source_vmid} -> {new_vmid} ({name})")

        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{source_vmid}/clone",
            data={
                "newid": new_vmid,
                "name": name,
                "full": 1 if full else 0,
                "description": description or f"ThreatSimGPT attack simulation VM: {name}"
            }
        )

        await self._wait_task(task)
        logger.info(f"Clone complete: VM {new_vmid}")

        return new_vmid

    async def create_vm(self, vmid: int, **kwargs) -> int:
        """
        Create a new VM (not from template).

        Args:
            vmid: VM ID
            **kwargs: VM configuration options

        Returns:
            VM ID
        """
        await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu",
            data={"vmid": vmid, **kwargs}
        )
        return vmid

    async def start_vm(self, vmid: int) -> None:
        """
        Start a VM.

        Args:
            vmid: VM ID to start
        """
        logger.info(f"Starting VM {vmid}")
        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/status/start"
        )
        await self._wait_task(task)
        logger.info(f"VM {vmid} started")

    async def stop_vm(self, vmid: int, timeout: int = 60) -> None:
        """
        Stop a VM gracefully (ACPI shutdown).

        Args:
            vmid: VM ID to stop
            timeout: Shutdown timeout in seconds
        """
        logger.info(f"Stopping VM {vmid}")
        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/status/shutdown",
            data={"timeout": timeout}
        )
        await self._wait_task(task, timeout=timeout + 30)
        logger.info(f"VM {vmid} stopped")

    async def force_stop_vm(self, vmid: int) -> None:
        """
        Force stop a VM (power off).

        Args:
            vmid: VM ID to force stop
        """
        logger.info(f"Force stopping VM {vmid}")
        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/status/stop"
        )
        await self._wait_task(task)
        logger.info(f"VM {vmid} force stopped")

    async def destroy_vm(self, vmid: int, purge: bool = True) -> None:
        """
        Destroy a VM completely.

        Args:
            vmid: VM ID to destroy
            purge: Also remove from backup jobs
        """
        logger.info(f"Destroying VM {vmid}")

        # Force stop if running
        try:
            status = await self.get_vm(vmid)
            if status.get("status") == "running":
                await self.force_stop_vm(vmid)
                await asyncio.sleep(2)
        except ProxmoxError:
            pass  # VM might not exist

        # Delete VM
        task = await self._request(
            "DELETE",
            f"/nodes/{self.config.node}/qemu/{vmid}",
            data={"purge": 1 if purge else 0}
        )
        await self._wait_task(task)
        logger.info(f"VM {vmid} destroyed")

    async def configure_vm(self, vmid: int, **kwargs) -> None:
        """
        Update VM configuration.

        Args:
            vmid: VM ID
            **kwargs: Configuration options (cores, memory, etc.)
        """
        await self._request(
            "PUT",
            f"/nodes/{self.config.node}/qemu/{vmid}/config",
            data=kwargs
        )

    # =========================================================================
    # Snapshot Management
    # =========================================================================

    async def create_snapshot(
        self,
        vmid: int,
        name: str,
        description: str = "",
        include_ram: bool = True
    ) -> str:
        """
        Create VM snapshot.

        Args:
            vmid: VM ID
            name: Snapshot name (alphanumeric)
            description: Optional description
            include_ram: Include RAM state (allows restore to running state)

        Returns:
            Snapshot name
        """
        logger.info(f"Creating snapshot '{name}' for VM {vmid}")

        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/snapshot",
            data={
                "snapname": name,
                "description": description or f"ThreatSimGPT snapshot: {name}",
                "vmstate": 1 if include_ram else 0
            }
        )
        await self._wait_task(task, timeout=300)
        logger.info(f"Snapshot '{name}' created for VM {vmid}")

        return name

    async def restore_snapshot(self, vmid: int, name: str) -> None:
        """
        Restore VM to snapshot.

        Args:
            vmid: VM ID
            name: Snapshot name to restore
        """
        logger.info(f"Restoring VM {vmid} to snapshot '{name}'")

        task = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/snapshot/{name}/rollback"
        )
        await self._wait_task(task, timeout=300)
        logger.info(f"VM {vmid} restored to snapshot '{name}'")

    async def list_snapshots(self, vmid: int) -> List[Dict[str, Any]]:
        """
        List VM snapshots.

        Args:
            vmid: VM ID

        Returns:
            List of snapshot info dicts
        """
        return await self._request(
            "GET",
            f"/nodes/{self.config.node}/qemu/{vmid}/snapshot"
        )

    async def delete_snapshot(self, vmid: int, name: str) -> None:
        """
        Delete a snapshot.

        Args:
            vmid: VM ID
            name: Snapshot name to delete
        """
        logger.info(f"Deleting snapshot '{name}' from VM {vmid}")

        task = await self._request(
            "DELETE",
            f"/nodes/{self.config.node}/qemu/{vmid}/snapshot/{name}"
        )
        await self._wait_task(task)
        logger.info(f"Snapshot '{name}' deleted from VM {vmid}")

    # =========================================================================
    # Console & Input
    # =========================================================================

    async def get_vnc_ticket(self, vmid: int) -> Dict[str, str]:
        """
        Get VNC connection ticket for console access.

        Args:
            vmid: VM ID

        Returns:
            Dict with 'ticket', 'port', 'user' for VNC connection
        """
        return await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/vncproxy"
        )

    async def get_spice_ticket(self, vmid: int) -> Dict[str, str]:
        """
        Get SPICE connection ticket.

        Args:
            vmid: VM ID

        Returns:
            Dict with SPICE connection details
        """
        return await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/spiceproxy"
        )

    async def send_key(self, vmid: int, key: str) -> None:
        """
        Send keyboard input to VM.

        Args:
            vmid: VM ID
            key: Key to send. Can be:
                - Single chars: 'a', 'b', '1'
                - Special: 'ret' (enter), 'tab', 'esc', 'spc' (space)
                - Combos: 'ctrl-c', 'alt-tab', 'ctrl-alt-del'
        """
        await self._request(
            "PUT",
            f"/nodes/{self.config.node}/qemu/{vmid}/sendkey",
            data={"key": key}
        )

    async def type_text(self, vmid: int, text: str, delay_ms: int = 50) -> None:
        """
        Type text into VM character by character.

        Args:
            vmid: VM ID
            text: Text to type
            delay_ms: Delay between keystrokes in milliseconds
        """
        key_map = {
            " ": "spc",
            "\n": "ret",
            "\t": "tab",
            "-": "minus",
            "=": "equal",
            "[": "bracket_left",
            "]": "bracket_right",
            ";": "semicolon",
            "'": "apostrophe",
            ",": "comma",
            ".": "dot",
            "/": "slash",
            "\\": "backslash",
        }

        for char in text:
            if char in key_map:
                key = key_map[char]
            elif char.isupper():
                key = f"shift-{char.lower()}"
            else:
                key = char

            await self.send_key(vmid, key)
            await asyncio.sleep(delay_ms / 1000)

    # =========================================================================
    # Guest Agent Operations
    # =========================================================================

    async def get_vm_ip(self, vmid: int) -> Optional[str]:
        """
        Get VM IP address from guest agent.

        Requires qemu-guest-agent installed and running in VM.

        Args:
            vmid: VM ID

        Returns:
            IP address string or None if not available
        """
        try:
            result = await self._request(
                "GET",
                f"/nodes/{self.config.node}/qemu/{vmid}/agent/network-get-interfaces"
            )

            for iface in result.get("result", []):
                name = iface.get("name", "")
                # Skip loopback
                if name in ("lo", "Loopback Pseudo-Interface 1"):
                    continue

                for addr in iface.get("ip-addresses", []):
                    if addr.get("ip-address-type") == "ipv4":
                        ip = addr.get("ip-address")
                        # Skip localhost
                        if ip and not ip.startswith("127."):
                            return ip

            return None

        except ProxmoxError as e:
            logger.debug(f"Could not get IP for VM {vmid}: {e}")
            return None

    async def wait_for_ip(self, vmid: int, timeout: int = 120) -> str:
        """
        Wait for VM to get an IP address.

        Args:
            vmid: VM ID
            timeout: Maximum wait time in seconds

        Returns:
            IP address

        Raises:
            ProxmoxError: If timeout reached
        """
        logger.info(f"Waiting for VM {vmid} to get IP address...")

        start = asyncio.get_event_loop().time()

        while True:
            ip = await self.get_vm_ip(vmid)
            if ip:
                logger.info(f"VM {vmid} has IP: {ip}")
                return ip

            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                raise ProxmoxError(f"Timeout waiting for VM {vmid} IP address")

            await asyncio.sleep(5)

    async def execute_guest_command(
        self,
        vmid: int,
        command: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Execute command via guest agent.

        Requires qemu-guest-agent installed in VM.

        Args:
            vmid: VM ID
            command: Shell command to execute
            timeout: Command timeout in seconds

        Returns:
            Dict with 'stdout', 'stderr', 'exit_code'
        """
        # Start command execution
        result = await self._request(
            "POST",
            f"/nodes/{self.config.node}/qemu/{vmid}/agent/exec",
            data={"command": command}
        )

        pid = result.get("pid")
        if not pid:
            raise ProxmoxError("Failed to start guest command")

        # Poll for completion
        start = asyncio.get_event_loop().time()

        while True:
            status = await self._request(
                "GET",
                f"/nodes/{self.config.node}/qemu/{vmid}/agent/exec-status",
                data={"pid": pid}
            )

            if status.get("exited"):
                return {
                    "stdout": status.get("out-data", ""),
                    "stderr": status.get("err-data", ""),
                    "exit_code": status.get("exitcode", -1)
                }

            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                raise ProxmoxError(f"Command timeout after {timeout}s: {command}")

            await asyncio.sleep(1)

    # =========================================================================
    # Utility Methods
    # =========================================================================

    async def get_next_vmid(self) -> int:
        """
        Get next available VM ID.

        Returns:
            Next available VM ID
        """
        result = await self._request("GET", "/cluster/nextid")
        return int(result)

    async def _wait_task(self, task_id: str, timeout: int = 300) -> None:
        """
        Wait for Proxmox task to complete.

        Args:
            task_id: Task UPID
            timeout: Maximum wait time in seconds

        Raises:
            ProxmoxError: If task fails or times out
        """
        if not task_id:
            return

        start = asyncio.get_event_loop().time()

        while True:
            status = await self._request(
                "GET",
                f"/nodes/{self.config.node}/tasks/{task_id}/status"
            )

            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status != "OK":
                    raise ProxmoxError(f"Task failed: {exit_status}")
                return

            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                raise ProxmoxError(f"Task timeout after {timeout}s: {task_id}")

            await asyncio.sleep(1)

    async def health_check(self) -> Dict[str, Any]:
        """
        Check Proxmox connection health.

        Returns:
            Dict with health status info
        """
        try:
            vms = await self.list_vms()
            return {
                "status": "healthy",
                "host": self.config.host,
                "node": self.config.node,
                "vm_count": len(vms),
                "connected": True
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "host": self.config.host,
                "node": self.config.node,
                "error": str(e),
                "connected": False
            }
