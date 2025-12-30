"""Data models for VM-based attack simulation.

This module provides Pydantic models and dataclasses for VM configuration,
state management, and attack results.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4

from pydantic import BaseModel, Field


class VMState(str, Enum):
    """VM operational states."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    SNAPSHOTTING = "snapshotting"
    RESTORING = "restoring"
    ERROR = "error"


class HypervisorType(str, Enum):
    """Supported hypervisor types."""
    PROXMOX = "proxmox"
    VMWARE = "vmware"
    VIRTUALBOX = "virtualbox"
    LIBVIRT = "libvirt"
    DOCKER = "docker"  # For container-based simulation
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class AttackPhase(str, Enum):
    """MITRE ATT&CK-aligned attack phases."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class VMConfig(BaseModel):
    """Configuration for a virtual machine."""

    name: str = Field(..., description="VM name")
    template: str = Field(..., description="Base template to clone from")
    os_type: str = Field("linux", description="Operating system type")

    # Resource specs
    cpu_cores: int = Field(2, ge=1, le=32)
    memory_gb: int = Field(4, ge=1, le=256)
    disk_gb: int = Field(40, ge=10, le=2000)

    # Network config
    network: str = Field("attack_network", description="Network to attach to")
    ip_address: Optional[str] = Field(None, description="Static IP if needed")

    # Credentials
    ssh_user: str = Field("root", description="SSH username")
    ssh_password: Optional[str] = Field(None, description="SSH password")
    ssh_key_path: Optional[str] = Field(None, description="Path to SSH private key")

    # VM role
    is_attacker: bool = Field(False, description="Is this an attacker VM?")
    is_target: bool = Field(False, description="Is this a target VM?")
    is_monitor: bool = Field(False, description="Is this a monitoring VM?")


class VMInfo(BaseModel):
    """Runtime information about a VM."""

    vm_id: str = Field(..., description="Unique VM identifier")
    name: str = Field(..., description="VM name")
    state: VMState = Field(VMState.STOPPED)
    os_type: str = Field("linux")
    ip_address: Optional[str] = Field(None)

    # Resource usage
    cpu_usage_percent: Optional[float] = Field(None)
    memory_usage_percent: Optional[float] = Field(None)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    config: Optional[VMConfig] = Field(None)
    snapshots: List[str] = Field(default_factory=list)


class CommandResult(BaseModel):
    """Result of executing a command on a VM."""

    command: str = Field(..., description="Command that was executed")
    stdout: str = Field("", description="Standard output")
    stderr: str = Field("", description="Standard error")
    exit_code: int = Field(0, description="Exit code")
    execution_time_ms: float = Field(0.0, description="Execution time in ms")

    # Optional extras
    screenshot: Optional[bytes] = Field(None, description="Screenshot after command")
    vm_id: str = Field("", description="VM where command ran")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        arbitrary_types_allowed = True

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.exit_code == 0


@dataclass
class AttackStep:
    """Single step in an attack plan."""

    phase: AttackPhase
    technique_id: str  # MITRE ATT&CK technique ID (e.g., T1595)
    technique_name: str
    description: str
    commands: List[str]
    success_indicators: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    timeout_seconds: int = 300

    # Execution state
    executed: bool = False
    success: bool = False
    output: str = ""
    error: Optional[str] = None


@dataclass
class AttackPlan:
    """Complete attack plan with multiple steps."""

    plan_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""

    # Attack configuration
    steps: List[AttackStep] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)

    # Target info
    target_vms: List[str] = field(default_factory=list)
    attacker_vm: str = ""

    # Timing
    timeout_minutes: int = 60
    created_at: datetime = field(default_factory=datetime.utcnow)

    # MITRE mapping
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class AgentState:
    """Current state of the AI attack agent."""

    current_vm: str = ""
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE

    # Progress tracking
    compromised_hosts: List[str] = field(default_factory=list)
    collected_credentials: List[Dict[str, Any]] = field(default_factory=list)
    discovered_services: List[Dict[str, Any]] = field(default_factory=list)
    discovered_users: List[str] = field(default_factory=list)

    # Objectives
    current_objective: str = ""
    completed_objectives: List[str] = field(default_factory=list)

    # History
    action_history: List[Dict[str, Any]] = field(default_factory=list)
    command_history: List[CommandResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # Session info
    session_start: datetime = field(default_factory=datetime.utcnow)
    last_action: Optional[datetime] = None


class AttackResult(BaseModel):
    """Final result of an attack simulation."""

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    plan_id: str = Field(..., description="ID of the attack plan")
    attack_name: str = Field(..., description="Name of the attack")

    # Timing
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = Field(None)
    duration_seconds: float = Field(0.0)

    # Results
    success: bool = Field(False)
    objectives_completed: List[str] = Field(default_factory=list)
    objectives_total: int = Field(0)
    success_rate: float = Field(0.0)

    # Findings
    compromised_hosts: List[str] = Field(default_factory=list)
    credentials_captured: int = Field(0)
    services_discovered: int = Field(0)

    # Logs
    action_count: int = Field(0)
    errors: List[str] = Field(default_factory=list)
    action_log: List[Dict[str, Any]] = Field(default_factory=list)

    # Analysis
    executive_summary: str = Field("")
    recommendations: List[str] = Field(default_factory=list)
    mitre_techniques_used: List[str] = Field(default_factory=list)

    # Detection
    alerts_generated: List[Dict[str, Any]] = Field(default_factory=list)
    detection_coverage: Dict[str, bool] = Field(default_factory=dict)


class InfrastructureConfig(BaseModel):
    """Configuration for VM attack infrastructure."""

    # Hypervisor settings
    hypervisor_type: HypervisorType = Field(HypervisorType.DOCKER)
    hypervisor_host: str = Field("localhost")
    hypervisor_port: int = Field(8006)
    hypervisor_user: str = Field("root")
    hypervisor_password: Optional[str] = Field(None)
    api_token: Optional[str] = Field(None)

    # Network settings
    attack_network_name: str = Field("threatsimgpt-attack-net")
    attack_network_subnet: str = Field("10.0.100.0/24")
    management_network_name: str = Field("threatsimgpt-mgmt-net")
    internet_access: bool = Field(False)  # Should be False for safety

    # VM templates
    attacker_template: str = Field("ubuntu-attacker")
    windows_target_template: str = Field("windows-target")
    linux_target_template: str = Field("ubuntu-target")
    monitor_template: str = Field("monitor-vm")

    # Resource limits
    max_concurrent_vms: int = Field(10)
    max_attack_duration_minutes: int = Field(120)
    auto_cleanup: bool = Field(True)

    # Safety settings
    require_approval_for_destructive: bool = Field(True)
    log_all_commands: bool = Field(True)
    snapshot_before_attack: bool = Field(True)
