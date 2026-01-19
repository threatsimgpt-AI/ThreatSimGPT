"""
MCP Server Configuration

Configuration classes for the ThreatSimGPT MCP server, including:
- Proxmox VE connection settings
- Network isolation configuration
- Safety controls and blocked commands
"""

from dataclasses import dataclass, field
from typing import List, Optional
import os


@dataclass
class ProxmoxConfig:
    """
    Proxmox VE connection configuration.

    Attributes:
        host: Proxmox server hostname or IP
        port: API port (default: 8006)
        user: API user (format: user@realm)
        token_name: API token name
        token_value: API token value (secret)
        node: Proxmox node name
        verify_ssl: Whether to verify SSL certificates
    """
    host: str = field(
        default_factory=lambda: os.environ.get("PROXMOX_HOST", "192.168.1.100")
    )
    port: int = field(
        default_factory=lambda: int(os.environ.get("PROXMOX_PORT", "8006"))
    )
    user: str = field(
        default_factory=lambda: os.environ.get("PROXMOX_USER", "threatsimgpt@pve")
    )
    token_name: str = field(
        default_factory=lambda: os.environ.get("PROXMOX_TOKEN_NAME", "automation")
    )
    token_value: str = field(
        default_factory=lambda: os.environ.get("PROXMOX_TOKEN_VALUE", "")
    )
    node: str = field(
        default_factory=lambda: os.environ.get("PROXMOX_NODE", "pve")
    )
    verify_ssl: bool = False

    def validate(self) -> bool:
        """Check if configuration is valid."""
        if not self.host:
            raise ValueError("PROXMOX_HOST is required")
        if not self.token_value:
            raise ValueError("PROXMOX_TOKEN_VALUE is required")
        return True


@dataclass
class NetworkConfig:
    """
    Network isolation configuration.

    CRITICAL: Attack simulations MUST be isolated from production networks.

    Attributes:
        attack_network: CIDR for isolated attack network
        attack_bridge: Proxmox bridge for attack network
        management_network: CIDR for management access
        allowed_networks: Networks that can be targeted
    """
    attack_network: str = "10.0.100.0/24"
    attack_bridge: str = "vmbr1"
    management_network: str = "192.168.1.0/24"
    allowed_networks: List[str] = field(
        default_factory=lambda: ["10.0.100.0/24"]
    )

    def is_allowed_target(self, ip: str) -> bool:
        """Check if IP is in allowed networks."""
        import ipaddress
        try:
            target = ipaddress.ip_address(ip)
            for network_str in self.allowed_networks:
                network = ipaddress.ip_network(network_str)
                if target in network:
                    return True
            return False
        except ValueError:
            return False


@dataclass
class SafetyConfig:
    """
    Safety controller configuration.

    Prevents dangerous operations that could:
    - Escape the isolated environment
    - Cause destructive damage
    - Access external networks

    Attributes:
        blocked_commands: Shell commands to block
        blocked_patterns: Regex patterns to block
        max_concurrent_vms: Maximum VMs allowed
        auto_destroy_hours: Hours before auto-cleanup
        require_approval: Scenarios requiring manual approval
    """
    blocked_commands: List[str] = field(default_factory=lambda: [
        # Destructive commands
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "dd if=/dev/zero",
        "dd if=/dev/random",
        "mkfs",
        "mkfs.ext4",
        "format c:",
        "del /f /s /q",

        # Fork bombs and resource exhaustion
        ":(){ :|:& };:",
        "fork()",

        # Network escapes
        "wget http://",
        "wget https://",
        "curl http://",
        "curl https://",

        # Reverse shells to external IPs
        "nc -e",
        "bash -i >& /dev/tcp/",

        # Container/VM escapes
        "docker run --privileged",
        "mount /dev/sda",
    ])

    blocked_patterns: List[str] = field(default_factory=lambda: [
        r"rm\s+-[rf]+\s+/\s*$",  # rm -rf /
        r">\s*/dev/[sh]d[a-z]",   # Write to disk device
        r"mkfs\.",                 # Format filesystem
        r"/dev/tcp/",              # Bash reverse shell
        r"nc\s+.*-e",              # Netcat exec
    ])

    max_concurrent_vms: int = 10
    auto_destroy_hours: int = 4

    require_approval: List[str] = field(default_factory=lambda: [
        "ransomware",
        "wiper",
        "destructive",
        "supply_chain",
    ])


@dataclass
class TemplateConfig:
    """
    VM template configuration.

    Maps template names to Proxmox VM IDs and default settings.
    """
    # NOTE: These are INTENTIONAL default credentials for isolated lab VMs
    # used in threat simulation training. They are NOT production credentials.
    templates: dict = field(default_factory=lambda: {
        "ubuntu-attacker": {
            "vmid": 9000,
            "description": "Ubuntu 24.04 with security tools",
            "cpu_cores": 4,
            "memory_mb": 8192,
            "default_user": "root",
            "default_password": "threatsimgpt",  # nosec B105 - intentional lab credential
            "tools": ["nmap", "metasploit", "gobuster", "nuclei", "hydra"]
        },
        "ubuntu-target": {
            "vmid": 9001,
            "description": "Ubuntu 24.04 vulnerable target",
            "cpu_cores": 2,
            "memory_mb": 4096,
            "default_user": "admin",
            "default_password": "vulnerable123",  # nosec B105 - intentional lab credential
        },
        "windows-target": {
            "vmid": 9002,
            "description": "Windows 11 vulnerable target",
            "cpu_cores": 2,
            "memory_mb": 4096,
            "default_user": "admin",
            "default_password": "vulnerable123",  # nosec B105 - intentional lab credential
        },
    })

    def get_template(self, name: str) -> dict:
        """Get template configuration by name."""
        if name not in self.templates:
            raise ValueError(f"Unknown template: {name}. Available: {list(self.templates.keys())}")
        return self.templates[name]


@dataclass
class MCPConfig:
    """
    Main MCP server configuration.

    Combines all configuration sections into a single config object.

    Usage:
        # From environment variables
        config = MCPConfig.from_env()

        # From YAML file
        config = MCPConfig.from_file("config.yaml")

        # Manual configuration
        config = MCPConfig(
            proxmox=ProxmoxConfig(host="192.168.1.100"),
            network=NetworkConfig(attack_network="10.0.100.0/24"),
        )
    """
    proxmox: ProxmoxConfig = field(default_factory=ProxmoxConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    templates: TemplateConfig = field(default_factory=TemplateConfig)

    # Server settings
    server_name: str = "threatsimgpt-vm"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "MCPConfig":
        """
        Load configuration from environment variables.

        Environment variables:
            PROXMOX_HOST, PROXMOX_PORT, PROXMOX_USER
            PROXMOX_TOKEN_NAME, PROXMOX_TOKEN_VALUE
            PROXMOX_NODE
        """
        return cls(
            proxmox=ProxmoxConfig(),
            network=NetworkConfig(),
            safety=SafetyConfig(),
            templates=TemplateConfig(),
        )

    @classmethod
    def from_file(cls, path: str) -> "MCPConfig":
        """
        Load configuration from YAML file.

        Args:
            path: Path to YAML configuration file

        Returns:
            MCPConfig instance
        """
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls(
            proxmox=ProxmoxConfig(**data.get("proxmox", {})),
            network=NetworkConfig(**data.get("network", {})),
            safety=SafetyConfig(**data.get("safety", {})),
            templates=TemplateConfig(templates=data.get("templates", {})),
            server_name=data.get("server_name", "threatsimgpt-vm"),
            log_level=data.get("log_level", "INFO"),
        )

    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        from dataclasses import asdict
        return asdict(self)

    def validate(self) -> bool:
        """Validate all configuration sections."""
        self.proxmox.validate()
        return True
